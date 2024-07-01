#!/usr/bin/env python3
import json
import argparse
from pathlib import Path
import os


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "filepath", type=str, help="path to skf-labs benchmark python directory"
    )
    parser.add_argument(
        "-s",
        "--sparse",
        dest="is_sparse",
        action="store_true",
        help="make individual markup for every benchmark project",
    )
    return parser.parse_args()


def load_cwe_mappings():
    mappings_path = (
        Path(__file__).resolve().parents[0]
        / "metadata"
        / "bentoo"
        / "taxonomies"
        / "sonarqube_rule_mapping.json"
    )
    with open(mappings_path.absolute().resolve(), "r") as mappings_f:
        mappings = json.load(mappings_f)
    return mappings["rule_mapping"]


def get_cwes(mappings, sq_id: str):
    if sq_id.find("xss") != -1:
        return ["CWE-79"]
    if sq_id == "S5998":
        return ["CWE-400", "CWE-1333"]
    match mappings.get(sq_id):
        case None:
            return None
        case cwe_ids:
            return list(map(lambda cwe_id: f"CWE-{cwe_id}", cwe_ids))


def empty_sarif(name):
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": name}}, "results": []}],
    }


def mk_result(kind, cwes, path, line):
    cwes_str = ",".join(cwes)
    return {
        "kind": kind,
        "ruleId": cwes_str,
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": line},
                }
            }
        ],
    }


def parse_truth_file(path, mappings, kind, region_keyword):
    with open(path.absolute().resolve(), "r") as truth_f:
        truth = json.load(truth_f)

    results = []
    for sq_id, regions in truth[region_keyword].items():
        prefix, sq_id = sq_id.split(":")

        if not prefix.startswith("python"):
            continue

        cwes = get_cwes(mappings, sq_id)
        if cwes is None:
            print(f"{path} {sq_id}: not presented")
            continue
        if len(cwes) == 0:
            print(f"{sq_id}: empty mapping")
            continue

        for region in regions:
            file_name = region["fileId"].split(":")[1]
            for line in region["lines"]:
                results.append(mk_result(kind, cwes, file_name, line))

    return results


def convert_markup(cwe_mappings):
    ground_truth_path = (
        Path(__file__).resolve().parents[0]
        / "metadata"
        / "sonar-benchmarks-scores"
        / "python"
        / "skf-labs-python"
    )
    subbenches_ground_truth_paths = [
        (Path(f.path), f.name) for f in os.scandir(ground_truth_path) if f.is_dir()
    ]
    resultss = []
    for path, name in subbenches_ground_truth_paths:
        ground_truth = path / "ground-truth.json"
        ignored_findings = path / "ignored-findings.json"

        results = []
        if ground_truth.is_file():
            results += parse_truth_file(
                ground_truth, cwe_mappings, "fail", "expectedIssues"
            )
        if ignored_findings.is_file():
            results += parse_truth_file(
                ignored_findings, cwe_mappings, "pass", "ignoredIssues"
            )

        subbench_name = name.split("skf-labs-python-")[1]
        resultss.append((subbench_name, results))

    return resultss


def write_sarif(benchmark_path, results):
    truth_sarif = empty_sarif("skf-labs-python")
    updated_results = truth_sarif["runs"][0]["results"]
    for subbench, result in results:
        artifact_location = result["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]
        correct_uri = f'{subbench}/{artifact_location["uri"]}'
        artifact_location["uri"] = correct_uri
        updated_results.append(result)

    truth_sarif_path = benchmark_path / "truth.sarif"
    with open(truth_sarif_path.absolute().resolve(), "w") as truth_sarif_f:
        json.dump(truth_sarif, truth_sarif_f, indent=2)


def main():
    args = parse_args()
    mappings = load_cwe_mappings()
    resultss = convert_markup(mappings)

    merged_results = []
    list(
        map(
            lambda name_results: (
                name := name_results[0],
                results := name_results[1],
                merged_results.extend([(name, result) for result in results]),
            ),
            resultss,
        )
    )
    write_sarif(Path(args.filepath), merged_results)


if __name__ == "__main__":
    main()
