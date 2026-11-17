module ClevisZfs
  # Lue au compile-time depuis `shard.yml` via le macro `read_file`.
  # Évite toute désynchronisation entre cette constante et shard.yml.
  VERSION = {{
              (read_file("#{__DIR__}/../../shard.yml")
                .lines
                .find(&.starts_with?("version:")) || "version: 0.0.0")
                .gsub(/^version:\s*/, "")
                .chomp
            }}
end
