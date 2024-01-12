## Example: FSNotify related symbols

In this example we process all btf files of the btfhub-archive repo to keep only the minimum amount of btf files required to capture all the possible variations, in terms of fetch arg field offsets, of the following three symbols `fsnotify`, `__fsnotify_parent` (can be also found as `fsnotify_parent` in some kernel versions), `fsnotify_nameremove` (exists only is some kernel versions). Also, all found btf files are going to get stripped, so they contain only the btf types required of the former three symbols.

#### Prepare [btfhub-archive](https://github.com/aquasecurity/btfhub-archive) repo:
```shell
git clone https://github.com/aquasecurity/btfhub-archive.git
cd btfhub-archive
export BTFHUB_ARCHIVE_REPO=$PWD
find . -iname "*.btf.tar.xz"  -exec sh -c 'tar xvf {} -C $(dirname {})' \;
```

#### Run the fsnotify symbol offset extractor:
```shell
go run ./examples/fsnotify/main.go -repo ${BTFHUB_ARCHIVE_REPO}
```