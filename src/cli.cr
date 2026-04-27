require "option_parser"
require "file_utils"
require "json"
require "./crystal_clevis_zfs"

# Convention (Aloli CLI UX): every long flag has a short equivalent;
# every subcommand has a short alias.
module CrystalClevisZfs::CLI
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
      puts "crystal-clevis-zfs #{CrystalClevisZfs::VERSION}"
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
    tang_url = ""
    key_store = DEFAULT_KEY_STORE
    do_init = false
    use_existing = false
    keyformat = "hex"
    compression = "lz4"
    mountpoint : String? = "none"

    OptionParser.parse(argv.dup) do |parser|
      parser.banner = "Usage: crystal-clevis-zfs bind -d DATASET -t TANG_URL (--init|--use-existing-key) [options]"
      parser.on("-d NAME", "--dataset=NAME", "ZFS dataset (e.g. zroot/zsys)") { |v| dataset = v }
      parser.on("-t URL", "--tang=URL", "Tang server URL") { |v| tang_url = v }
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

    if dataset.empty? || tang_url.empty?
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

    if do_init
      key = CrystalClevisZfs::Zfs.random_key_hex
      tang = CrystalClevisZfs::TangClient.new(tang_url)
      jwe = tang.bind(key)

      Dir.mkdir_p(key_store)
      File.chmod(key_store, 0o700)
      jwe_path = jwe_path_for(key_store, dataset)
      File.write(jwe_path, jwe)
      File.chmod(jwe_path, 0o600)

      CrystalClevisZfs::Zfs.create_encrypted(
        dataset: dataset,
        key_hex: key,
        compression: compression,
        mountpoint: mountpoint,
      )

      puts "bound #{dataset} -> #{jwe_path} (Tang: #{tang_url})"
    else
      STDERR.puts "--use-existing-key not implemented yet"
      return 70
    end
    0
  rescue ex
    STDERR.puts "bind failed: #{ex.message}"
    1
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

    if CrystalClevisZfs::Zfs.key_loaded?(dataset)
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
    key_bytes = if CrystalClevisZfs::SssBinder.is_sss?(jwe)
                  CrystalClevisZfs::SssBinder.recover(jwe)
                else
                  header_b64 = jwe.split('.').first
                  header = Hash(String, JSON::Any).from_json(String.new(CrystalJose::Utils.base64url_decode(header_b64)))
                  tang_url = header["clevis"].as_h["tang"].as_h["url"].as_s
                  CrystalClevisZfs::TangClient.new(tang_url).recover(jwe)
                end
    key = String.new(key_bytes)

    CrystalClevisZfs::Zfs.load_key(dataset, key)
    CrystalClevisZfs::Zfs.mount_recursive(dataset) unless no_mount

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

exit CrystalClevisZfs::CLI.run(ARGV) if PROGRAM_NAME.includes?("crystal-clevis-zfs") || PROGRAM_NAME.includes?("cli")
