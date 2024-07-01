#!/bin/bash

requireCommand() {
  if ! command -v "$1" &> /dev/null
  then
    echo "$1 is required. Please install it and then try again."
    exit 1
  fi
}

requireCommand git
requireCommand docker
requireCommand python3

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
BASE_DIR="$(cd "$SCRIPT_DIR"/../../../../ && pwd)"

if [ ! -d "$BASE_DIR/skf-labs" ]; then
  echo "Run scripts/benchmarks/skf-labs/bootstrap.sh beforehand"
  exit 1
fi

EXIT_ON_ERROR="false"

for OPT in "$@"; do
  if [[ "$OPT" = *"--exit-on-error"* ]]; then
      EXIT_ON_ERROR="true"
      shift 1
  fi
done

if [[ "$EXIT_ON_ERROR" = "true" ]]; then
  set -e
fi

cd "$BASE_DIR"

(
  cd "$SCRIPT_DIR";
  if [ ! -d "metadata" ]; then
    mkdir metadata
  fi
  cd metadata;

  # cloning markup part
  if [ ! -d "sonar-benchmarks-scores" ]; then
    git clone --filter=blob:none --sparse https://github.com/SonarSource/sonar-benchmarks-scores.git
    (
      cd sonar-benchmarks-scores;
      git sparse-checkout add python/skf-labs-python;
      cd python/skf-labs-python;
      git reset --hard f0cfec64a23908d4dde0720d73c91ce97fc7b6fd
    )
  fi

  # cloning mappings part
  if [ ! -d "bentoo" ]; then
    git clone --filter=blob:none --sparse https://github.com/flawgarden/bentoo.git
    (
      cd bentoo;
      git sparse-checkout add taxonomies;
      cd taxonomies;
      git reset --hard b74ad08d034cce82a8d6afe60e27198b0e0e9a2b
    )
  fi
)

(cd "$BASE_DIR"; ./scripts/benchmarks/skf-labs/python/markup.py "skf-labs/python")
