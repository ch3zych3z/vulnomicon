SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
BASE_DIR="$(cd $SCRIPT_DIR/.. && pwd)"

cd $BASE_DIR;

if [ ! -f "bentoo" ]; then
    echo "Please run bentoo.sh beforehand"
fi

if [ ! -d "tool_runners" ]; then
    echo "Please run bentoo.sh beforehand"
fi

PATH=$PATH:$(pwd)

bentoo template --tools tool_runners/tools.toml BenchmarkJava-mutated > BenchmarkJava-mutated/runs.toml
bentoo bench --tools tool_runners/tools.toml --runs BenchmarkJava-mutated/runs.toml --timeout 1200 BenchmarkJava-mutated-output
