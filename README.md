# Tracing KProbes from BTF (tk-btf)
[![Build status](https://badge.buildkite.com/127fe118a0ca01517075701041070b66e1a6c27322132658db.svg)](https://buildkite.com/elastic/tk-btf)

`tk-btf` is a Go package to fabricate the string representation of [Linux tracing kprobes](https://docs.kernel.org/trace/kprobetrace.html#usage-examples) based on [BTF](https://docs.kernel.org/bpf/btf.html) files.

## Quick Start

To try out `tk-btf` have a look at the [examples](examples) folder.

## License

This software is licensed under the Apache License, version 2 ("ALv2"), quoted below.

Copyright 2023-2024 Elasticsearch <https://www.elastic.co>

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use this file except in compliance with the License. You may obtain a copy of
the License at

> http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.

This repository includes dependencies/submodules whose licenses are listed in [LICENSE.txt](LICENSE.txt).