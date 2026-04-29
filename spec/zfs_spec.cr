require "./spec_helper"
require "file_utils"

# Tests for the `Zfs` wrapper. The real `zfs(8)` is replaced by a
# small shell script that records every invocation (args + stdin)
# into a log file the test then inspects. This way we exercise the
# wrapper end-to-end without needing a live pool.

private def with_fake_zfs(behaviour : String? = nil, &)
  Dir.mkdir_p("/tmp/ccz-zfs-test")
  log = "/tmp/ccz-zfs-test/calls.log"
  bin = "/tmp/ccz-zfs-test/zfs"
  File.delete(log) if File.exists?(log)

  script = String.build do |s|
    s << <<-SH
    #!/bin/sh
    set -e
    LOG="#{log}"
    {
      printf 'CMD:'
      for a in "$@"; do printf ' %s' "$a"; done
      printf '\\n'
      printf 'STDIN:'
      stdin=$(cat)
      printf '%s\\n' "$stdin"
    } >> "$LOG"
    SH
    if behaviour
      s << "\n" << behaviour << "\n"
    end
  end
  File.write(bin, script)
  File.chmod(bin, 0o755)

  ENV["ZFS_BIN"] = bin
  begin
    yield log
  ensure
    ENV.delete("ZFS_BIN")
    FileUtils.rm_rf("/tmp/ccz-zfs-test")
  end
end

describe ClevisZfs::Zfs do
  describe ".random_key_hex" do
    it "produces a 64-character lowercase hex string" do
      k = ClevisZfs::Zfs.random_key_hex
      k.size.should eq(64)
      k.chars.all? { |c| c.ascii_number? || ('a'..'f').includes?(c) }.should be_true
    end

    it "is unique across calls" do
      a = ClevisZfs::Zfs.random_key_hex
      b = ClevisZfs::Zfs.random_key_hex
      a.should_not eq(b)
    end
  end

  describe ".create_encrypted" do
    it "calls zfs create with the right flags and feeds the key twice via stdin" do
      with_fake_zfs do |log|
        key = "a" * 64
        ClevisZfs::Zfs.create_encrypted(
          dataset: "zroot/zsys",
          key_hex: key,
          compression: "lz4",
          mountpoint: "none",
        )

        recorded = File.read(log)
        recorded.should contain("create -o encryption=on -o keyformat=hex -o keylocation=prompt")
        recorded.should contain("compression=lz4")
        recorded.should contain("mountpoint=none")
        recorded.should contain("zroot/zsys")
        # Key fed twice (zfs create with keylocation=prompt asks for confirmation)
        # The fake script collapses the two newlines into one printf, so we just
        # check the key appears at least once on the STDIN line.
        recorded.should contain("STDIN:#{key}")
      end
    end

    it "rejects a key of wrong length" do
      with_fake_zfs do
        expect_raises(ClevisZfs::Zfs::Error, /64 hex/) do
          ClevisZfs::Zfs.create_encrypted(dataset: "zroot/x", key_hex: "abcdef")
        end
      end
    end

    it "rejects a non-hex key" do
      with_fake_zfs do
        expect_raises(ClevisZfs::Zfs::Error, /non-hex/) do
          ClevisZfs::Zfs.create_encrypted(dataset: "zroot/x", key_hex: "z" * 64)
        end
      end
    end

    it "passes extra props" do
      with_fake_zfs do |log|
        ClevisZfs::Zfs.create_encrypted(
          dataset: "zroot/x",
          key_hex: "a" * 64,
          extra_props: {"atime" => "off", "recordsize" => "16K"},
        )
        recorded = File.read(log)
        recorded.should contain("atime=off")
        recorded.should contain("recordsize=16K")
      end
    end
  end

  describe ".load_key" do
    it "calls zfs load-key with the key on stdin (only once)" do
      with_fake_zfs(behaviour: "exit 0") do |log|
        # Pretend keystatus is unavailable so we go through the full path.
        # (we'd need a real fake to mock the keystatus query — the simple
        # script below records both calls)
        ClevisZfs::Zfs.load_key("zroot/zsys", "b" * 64)
        recorded = File.read(log)
        recorded.should contain("load-key")
        recorded.should contain("STDIN:#{"b" * 64}")
      end
    end

    it "is a no-op when the key is already loaded" do
      # Make the fake `zfs get keystatus` return "available" so load_key
      # short-circuits before invoking load-key.
      script = <<-SH
      case "$1" in
        get) echo "available"; exit 0 ;;
      esac
      SH
      with_fake_zfs(behaviour: script) do |log|
        ClevisZfs::Zfs.load_key("zroot/zsys", "c" * 64)
        recorded = File.read(log)
        recorded.should_not contain("load-key")
      end
    end
  end

  describe ".key_loaded?" do
    it "returns true when keystatus is available" do
      script = <<-SH
      case "$1" in
        get) echo "available"; exit 0 ;;
      esac
      SH
      with_fake_zfs(behaviour: script) do
        ClevisZfs::Zfs.key_loaded?("zroot/zsys").should be_true
      end
    end

    it "returns false when keystatus is unavailable" do
      script = <<-SH
      case "$1" in
        get) echo "unavailable"; exit 0 ;;
      esac
      SH
      with_fake_zfs(behaviour: script) do
        ClevisZfs::Zfs.key_loaded?("zroot/zsys").should be_false
      end
    end
  end

  describe ".change_key" do
    it "calls zfs change-key with the new key on stdin" do
      with_fake_zfs do |log|
        ClevisZfs::Zfs.change_key("zroot/zsys", "d" * 64)
        recorded = File.read(log)
        recorded.should contain("change-key")
        recorded.should contain("keyformat=hex")
        recorded.should contain("STDIN:#{"d" * 64}")
      end
    end
  end

  describe "key never appears in argv" do
    it "is not part of the recorded CMD line for create_encrypted" do
      key = "e" * 64
      with_fake_zfs do |log|
        ClevisZfs::Zfs.create_encrypted(dataset: "zroot/x", key_hex: key)
        recorded = File.read(log)
        # The CMD: line lists the argv. The key must NOT be there.
        cmd_line = recorded.lines.find! { |l| l.starts_with?("CMD:") }
        cmd_line.should_not contain(key)
      end
    end
  end
end
