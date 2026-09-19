This is a csv enrichment processor for Wazuh to do lookups.
Building it into Filebeat

Wazuh's Filebeat is a custom build of elastic/beats tag v7.10.2, not the latest upstream Filebeat, so this processor has to be compiled into a binary built from that same tag.
 Get elastic/beats at v7.10.2 (tarball avoids some git-over-HTTP/2
 transfer issues seen on slower/unstable connections; git clone works too if your network handles it fine)
```bash
curl -L --http1.1 -o beats-v7.10.2.tar.gz \
  https://github.com/elastic/beats/archive/refs/tags/v7.10.2.tar.gz
mkdir beats-build && tar -xzf beats-v7.10.2.tar.gz -C beats-build --strip-components=1
cd beats-build
```
# Apply this repo's patch
```bash
git apply /path/to/0001-add-csv_enrich-processor.patch
```
# Build
```bash
cd filebeat
GOOS=linux GOARCH=amd64 go build -o filebeat .
```
Then swap the resulting binary into place on your Wazuh manager (back up the original first):
```bash
sudo systemctl stop filebeat
sudo cp /usr/share/filebeat/bin/filebeat /usr/share/filebeat/bin/filebeat.bak
sudo cp ./filebeat /usr/share/filebeat/bin/filebeat
sudo chown root:root /usr/share/filebeat/bin/filebeat
sudo chmod 755 /usr/share/filebeat/bin/filebeat
sudo /usr/share/filebeat/bin/filebeat test config -c /etc/filebeat/filebeat.yml
sudo systemctl start filebeat
```
-------- Usage ------ 
```bash
processors:
  - csv_enrich:
      file: /etc/filebeat/enrich/users.csv
      lookup_field: user
      key_field: parsed_message.data.user
      fields: ["Department", "vlan_address", "Role"]
      target_prefix: user
      ignore_case: true
      ignore_missing: true
      reload_interval: 30s
```

| Option            | Required | Default | Description |
|-------------------|----------|---------|-------------|
| `file`             | yes      | —       | Path to the CSV file. First row must be a header row. |
| `lookup_field`     | yes      | —       | CSV column name used as the join key. |
| `key_field`        | yes      | —       | Dotted event field to read and match against lookup_field. |
| `fields`           | yes      | —       | CSV columns to copy onto the event on a match. |
| `target_prefix`    | no       | none    | Prefix added to each copied field name. |
| `ignore_case`      | no       | true    | Uppercase both sides before matching. |
| `ignore_missing`   | no       | true    | If false, a missing key_field errors instead of passing the event through. |
| `overwrite_keys`   | no       | true    | If false, leaves an existing event field untouched instead of overwriting it. |
| `reload_interval`  | no       | 30s     | How often to check the CSV file for changes. 0 disables reloading. |
