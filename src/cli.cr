require "option_parser"
require "file_utils"
require "json"
require "./clevis_zfs"

# Convention (Aloli CLI UX): every long flag has a short equivalent;
# every subcommand has a short alias.
module ClevisZfs::CLI
  extend self

  DEFAULT_KEY_STORE = "/var/db/crystal-clevis-zfs"

  def run(argv : Array(String)) : Int32
    if argv.empty?
      print_global_help(STDERR)
      return 64
    end

    case argv.first
    when "bind", "b"
      bind(argv[1..-1])
    when "unlock", "u"
      unlock(argv[1..-1])
    when "version", "v", "--version", "-V"
      puts "crystal-clevis-zfs #{ClevisZfs::VERSION}"
      0
    when "help", "h", "--help", "-h"
      print_global_help(STDOUT)
      0
    else
      STDERR.puts "unknown subcommand: #{argv.first}"
      print_global_help(STDERR)
      64
    end
  end

  def bind(argv : Array(String)) : Int32
    dataset = ""
    tang_urls = [] of String
    threshold = 0
    key_store = DEFAULT_KEY_STORE
    do_init = false
    use_existing = false
    keyformat = "hex"
    compression = "lz4"
    mountpoint : String? = "none"

    OptionParser.parse(argv.dup) do |parser|
      parser.banner = "Usage: crystal-clevis-zfs bind -d DATASET -t TANG_URL [-t TANG_URL ...] (--init|--use-existing-key) [options]"
      parser.on("-d NAME", "--dataset=NAME", "ZFS dataset (e.g. zroot/zsys)") { |v| dataset = v }
      parser.on("-t URL", "--tang=URL", "Tang server URL (repeat for multiple Tangs)") { |v| tang_urls << v }
      parser.on("-k K", "--threshold=K", "Threshold K (Tangs required to unlock); default 1") { |v| threshold = v.to_i }
      parser.on("-i", "--init", "Generate a fresh key and create the encrypted dataset") { do_init = true }
      parser.on("-e", "--use-existing-key", "Enroll the key of an existing encrypted dataset") { use_existing = true }
      parser.on("-s PATH", "--key-store=PATH", "JWE storage directory (default: #{DEFAULT_KEY_STORE})") { |v| key_store = v }
      parser.on("-f FMT", "--keyformat=FMT", "ZFS keyformat: hex (default) or raw") { |v| keyformat = v }
      parser.on("-c MODE", "--compression=MODE", "ZFS compression: lz4 (default), zstd-3, off") { |v| compression = v }
      parser.on("-m PATH", "--mountpoint=PATH", "ZFS mountpoint (default: none)") { |v| mountpoint = v == "none" ? "none" : v }
      parser.on("-h", "--help", "Show this help") do
        puts parser
        exit 0
      end
      parser.invalid_option do |flag|
        STDERR.puts "invalid option: #{flag}"
        STDERR.puts parser
        exit 64
      end
    end

    if dataset.empty? || tang_urls.empty?
      STDERR.puts "missing -d/--dataset or -t/--tang"
      return 64
    end
    if do_init == use_existing
      STDERR.puts "exactly one of --init or --use-existing-key is required"
      return 64
    end
    unless keyformat == "hex"
      STDERR.puts "v0.1 only supports --keyformat=hex (got #{keyformat})"
      return 64
    end

    threshold = 1 if threshold == 0
    if threshold > tang_urls.size
      STDERR.puts "threshold (#{threshold}) cannot exceed the number of -t/--tang flags (#{tang_urls.size})"
      return 64
    end

    if do_init
      key = ClevisZfs::Zfs.random_key_hex
      jwe = if tang_urls.size == 1 && threshold == 1
              ClevisZfs::TangClient.new(tang_urls.first).bind(key)
            else
              ClevisZfs::SssBinder.bind(key, tang_urls, threshold: threshold)
            end

      Dir.mkdir_p(key_store)
      File.chmod(key_store, 0o700)
      jwe_path = jwe_path_for(key_store, dataset)
      File.write(jwe_path, jwe)
      File.chmod(jwe_path, 0o600)

      ClevisZfs::Zfs.create_encrypted(
        dataset: dataset,
        key_hex: key,
        compression: compression,
        mountpoint: mountpoint,
      )

      summary = if tang_urls.size == 1
                  "Tang: #{tang_urls.first}"
                else
                  "#{tang_urls.size} Tangs, threshold #{threshold}"
                end
      puts "bound #{dataset} -> #{jwe_path} (#{summary})"
    else
      bind_use_existing(dataset, tang_urls, threshold, key_store)
    end
    0
  rescue ex
    STDERR.puts "bind failed: #{ex.message}"
    1
  end

  # `--use-existing-key` flow: the dataset is already encrypted and
  # its key is currently loaded. We read it via `zfs get keylocation`,
  # enroll it through Tang, and write the JWE. The key never appears
  # in argv at any point.
  private def bind_use_existing(dataset : String, tang_urls : Array(String),
                                threshold : Int32, key_store : String) : Nil
    raise "dataset #{dataset} is not encrypted" unless ClevisZfs::Zfs.encrypted?(dataset)
    raise "dataset #{dataset} key is not loaded; run `zfs load-key` first" unless ClevisZfs::Zfs.key_loaded?(dataset)

    keylocation = ClevisZfs::Zfs.get_property(dataset, "keylocation") ||
                  raise "could not read keylocation of #{dataset}"
    unless keylocation.starts_with?("file://")
      raise "expected keylocation=file://..., got '#{keylocation}'. " \
            "Use `zfs change-key -o keylocation=file:///path/to/key` first."
    end
    key_path = keylocation.sub("file://", "")
    raise "key file #{key_path} not readable" unless File::Info.readable?(key_path)

    raw = File.read(key_path).strip
    # Accept either 64 hex chars or 32 binary bytes (then encode to hex).
    key_hex = if raw.bytesize == 64 && raw.chars.all? { |c| c.ascii_number? || ('a'..'f').includes?(c.downcase) }
                raw.downcase
              elsif raw.bytesize == 32
                raw.to_slice.hexstring
              else
                raise "key file format not recognized (expected 64 hex chars or 32 raw bytes, got #{raw.bytesize} bytes)"
              end

    jwe = if tang_urls.size == 1 && threshold == 1
            ClevisZfs::TangClient.new(tang_urls.first).bind(key_hex)
          else
            ClevisZfs::SssBinder.bind(key_hex, tang_urls, threshold: threshold)
          end

    Dir.mkdir_p(key_store)
    File.chmod(key_store, 0o700)
    jwe_path = jwe_path_for(key_store, dataset)
    File.write(jwe_path, jwe)
    File.chmod(jwe_path, 0o600)

    summary = if tang_urls.size == 1
                "Tang: #{tang_urls.first}"
              else
                "#{tang_urls.size} Tangs, threshold #{threshold}"
              end
    puts "enrolled existing key of #{dataset} -> #{jwe_path} (#{summary})"
  end

  def unlock(argv : Array(String)) : Int32
    dataset = ""
    key_store = DEFAULT_KEY_STORE
    no_mount = false

    OptionParser.parse(argv.dup) do |parser|
      parser.banner = "Usage: crystal-clevis-zfs unlock -d DATASET [options]"
      parser.on("-d NAME", "--dataset=NAME", "ZFS dataset to unlock") { |v| dataset = v }
      parser.on("-s PATH", "--key-store=PATH", "JWE storage directory (default: #{DEFAULT_KEY_STORE})") { |v| key_store = v }
      parser.on("-n", "--no-mount", "Load the key but do not mount") { no_mount = true }
      parser.on("-h", "--help", "Show this help") do
        puts parser
        exit 0
      end
      parser.invalid_option do |flag|
        STDERR.puts "invalid option: #{flag}"
        STDERR.puts parser
        exit 64
      end
    end

    if dataset.empty?
      STDERR.puts "missing -d/--dataset"
      return 64
    end

    if ClevisZfs::Zfs.key_loaded?(dataset)
      puts "#{dataset} key already loaded; nothing to do"
      return 0
    end

    jwe_path = jwe_path_for(key_store, dataset)
    unless File.exists?(jwe_path)
      STDERR.puts "no JWE found at #{jwe_path}; was this dataset ever bound?"
      return 1
    end
    jwe = File.read(jwe_path)

    # Auto-detect SSS vs single Tang from the header (forward-compat
    # with v0.2 even if the CLI for v0.1 only produces single-Tang).
    key_bytes = if ClevisZfs::SssBinder.is_sss?(jwe)
                  ClevisZfs::SssBinder.recover(jwe)
                else
                  header_b64 = jwe.split('.').first
                  header = Hash(String, JSON::Any).from_json(String.new(Jose::Utils.base64url_decode(header_b64)))
                  tang_url = header["clevis"].as_h["tang"].as_h["url"].as_s
                  ClevisZfs::TangClient.new(tang_url).recover(jwe)
                end
    key = String.new(key_bytes)

    ClevisZfs::Zfs.load_key(dataset, key)
    ClevisZfs::Zfs.mount_recursive(dataset) unless no_mount

    puts "unlocked #{dataset}#{no_mount ? " (no-mount)" : ""}"
    0
  rescue ex
    STDERR.puts "unlock failed: #{ex.message}"
    1
  end

  # Sanitize the dataset name into a flat filename: replace `/` with `__`.
  private def jwe_path_for(key_store : String, dataset : String) : String
    File.join(key_store, "#{dataset.gsub('/', "__")}.jwe")
  end

  private def print_global_help(io : IO)
    io.puts "Usage: crystal-clevis-zfs SUBCOMMAND [options]"
    io.puts
    io.puts "Subcommands:"
    io.puts "  bind, b      Bind a ZFS dataset to a Tang server"
    io.puts "  unlock, u    Load the key of a previously bound dataset"
    io.puts "  version, v   Print version"
    io.puts "  help, h      Show this help"
    io.puts
    io.puts "Run `crystal-clevis-zfs SUBCOMMAND -h` for subcommand-specific options."
  end
end

exit ClevisZfs::CLI.run(ARGV) if PROGRAM_NAME.includes?("crystal-clevis-zfs") || PROGRAM_NAME.includes?("cli")
