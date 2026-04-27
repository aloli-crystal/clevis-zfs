require "process"
require "random/secure"

module CrystalClevisZfs
  # Thin wrapper around `zfs(8)` for native-encryption operations.
  #
  # Discipline on the key material (see `crystal-clevis-zfs-specs.adoc`
  # § « Discipline de la clé en mémoire ») :
  #
  # * Never passed as a CLI argument (would leak through `ps`).
  # * Never set in the environment of a child process.
  # * Always written to the child's stdin and the pipe is closed
  #   immediately afterwards.
  # * The Crystal `String` carrying the key is overwritten with zeros
  #   before returning.
  module Zfs
    extend self

    class Error < Exception
    end

    # Returns the path to the zfs(8) binary. Override `ZFS_BIN` for
    # tests so we can exercise the wrapper without a real pool.
    def binary : String
      ENV["ZFS_BIN"]? || "/sbin/zfs"
    end

    # Generate a fresh 32-byte key encoded as 64 hex chars (the format
    # ZFS expects when keyformat=hex).
    def random_key_hex : String
      Random::Secure.hex(32)
    end

    # Create a new encrypted dataset. The key is fed to `zfs create`
    # via stdin (twice — ZFS prompts then asks for confirmation).
    #
    # The dataset must not already exist; create_encrypted does NOT
    # mount it (mountpoint defaults to "none" so children mount but
    # the parent doesn't).
    def create_encrypted(dataset : String,
                         key_hex : String,
                         compression : String = "lz4",
                         mountpoint : String? = "none",
                         extra_props : Hash(String, String) = {} of String => String) : Nil
      validate_key_hex!(key_hex)

      args = [binary, "create",
              "-o", "encryption=on",
              "-o", "keyformat=hex",
              "-o", "keylocation=prompt"]
      args << "-o" << "compression=#{compression}" unless compression == "off"
      if mp = mountpoint
        args << "-o" << "mountpoint=#{mp}"
      end
      extra_props.each { |k, v| args << "-o" << "#{k}=#{v}" }
      args << dataset

      run_with_key_on_stdin(args, key_hex, prompt_count: 2)
    end

    # Load the key for an existing encrypted dataset. Idempotent: a
    # second call with the dataset already loaded is a no-op.
    def load_key(dataset : String, key_hex : String) : Nil
      validate_key_hex!(key_hex)
      return if key_loaded?(dataset)

      args = [binary, "load-key", "-L", "prompt", dataset]
      run_with_key_on_stdin(args, key_hex, prompt_count: 1)
    end

    # Unload (= forget in-memory) the key for `dataset`. Mounted
    # datasets that depend on the key must be unmounted first; that
    # is the caller's responsibility.
    def unload_key(dataset : String) : Nil
      run_no_input!([binary, "unload-key", dataset])
    end

    # Replace the encryption key on an encrypted dataset. The old key
    # must already be loaded (keystatus = available); the new key is
    # piped via stdin.
    def change_key(dataset : String, new_key_hex : String) : Nil
      validate_key_hex!(new_key_hex)
      args = [binary, "change-key",
              "-o", "keyformat=hex",
              "-o", "keylocation=prompt",
              dataset]
      run_with_key_on_stdin(args, new_key_hex, prompt_count: 2)
    end

    # True if the dataset's keystatus is "available" (= key loaded).
    def key_loaded?(dataset : String) : Bool
      keystatus(dataset) == "available"
    end

    # True if the dataset exists and is encrypted (regardless of
    # whether the key is currently loaded).
    def encrypted?(dataset : String) : Bool
      out, _ = capture([binary, "get", "-H", "-o", "value", "encryption", dataset])
      return false if out.nil?
      out.strip != "off" && out.strip != "-"
    end

    # `zfs get keystatus` — returns "available", "unavailable", "-",
    # or nil if the dataset does not exist.
    def keystatus(dataset : String) : String?
      get_property(dataset, "keystatus")
    end

    # Generic `zfs get -H -o value <prop> <dataset>`. Returns the
    # value (stripped) or nil if the dataset / property doesn't exist.
    def get_property(dataset : String, property : String) : String?
      out, ok = capture([binary, "get", "-H", "-o", "value", property, dataset])
      return nil unless ok
      out.try(&.strip)
    end

    # Mount the dataset and all its children that are encrypted under
    # the same encryption root, using `zfs mount -a -l`. The `-l` flag
    # automatically loads any keys for which keylocation can be read
    # non-interactively; in our setup the key has already been loaded
    # via `load_key`, so this is just the mount step.
    def mount_recursive(parent : String) : Nil
      run_no_input!([binary, "mount", "-l", parent])
      # Mount children: zfs mount -a -l would mount everything, but
      # we restrict to descendants of `parent`.
      out, _ = capture([binary, "list", "-H", "-r", "-o", "name", parent])
      return unless out
      out.each_line do |line|
        ds = line.strip
        next if ds.empty? || ds == parent
        # Best-effort mount; some children may have mountpoint=none.
        Process.run(binary, ["mount", ds],
          output: Process::Redirect::Close,
          error: Process::Redirect::Close)
      end
    end

    private def validate_key_hex!(key_hex : String) : Nil
      raise Error.new("key must be exactly 64 hex chars, got #{key_hex.bytesize}") unless key_hex.bytesize == 64
      raise Error.new("key contains non-hex characters") unless key_hex.chars.all? { |c| c.ascii_number? || ('a'..'f').includes?(c.downcase) }
    end

    # Run a `zfs` subcommand, writing `key_hex` (followed by a newline)
    # to its stdin `prompt_count` times. The string is scrubbed
    # immediately after the pipe is closed.
    private def run_with_key_on_stdin(args : Array(String), key_hex : String, prompt_count : Int32) : Nil
      payload = String.build(prompt_count * (key_hex.bytesize + 1)) do |io|
        prompt_count.times do
          io << key_hex
          io << '\n'
        end
      end

      stderr = IO::Memory.new
      status = Process.run(args[0], args[1..-1],
        input: IO::Memory.new(payload),
        output: Process::Redirect::Close,
        error: stderr)
      scrub!(payload)

      unless status.success?
        raise Error.new("#{args.join(' ')} failed (exit #{status.exit_code}): #{stderr.to_s.strip}")
      end
    end

    private def run_no_input!(args : Array(String)) : Nil
      stderr = IO::Memory.new
      status = Process.run(args[0], args[1..-1],
        input: Process::Redirect::Close,
        output: Process::Redirect::Close,
        error: stderr)
      unless status.success?
        raise Error.new("#{args.join(' ')} failed (exit #{status.exit_code}): #{stderr.to_s.strip}")
      end
    end

    private def capture(args : Array(String)) : Tuple(String?, Bool)
      stdout = IO::Memory.new
      status = Process.run(args[0], args[1..-1],
        input: Process::Redirect::Close,
        output: stdout,
        error: Process::Redirect::Close)
      {stdout.to_s, status.success?}
    rescue
      {nil, false}
    end

    # Best-effort wipe of a Crystal String's heap bytes. Crystal does
    # not expose mlock/munlock; this at least limits the window during
    # which the key can leak from a memory dump.
    private def scrub!(s : String) : Nil
      ptr = s.to_unsafe
      ptr.clear(s.bytesize)
    end
  end
end
