#!/usr/bin/env python3

"""
Looks up N previous releases and outputs a Helm chart version for the most recent patch for each found release.
"""

import json
import logging
import pathlib
import re
import subprocess
import sys

from collections import namedtuple

this_script_dir = pathlib.Path(__file__).parent
repo_root = this_script_dir.parent

helm_repo_name = "temp-stackrox-oss-repo-should-not-see-me"

add_repo_cmd = f"helm repo add {helm_repo_name} https://raw.githubusercontent.com/stackrox/helm-charts/main/opensource"
update_repo_cmd = "helm repo update"
search_cmd = f"helm search repo {helm_repo_name} --versions --output json"
remove_repo_cmd = f"helm repo remove {helm_repo_name}"

Version = namedtuple("Version", ["major", "minor", "patch"])

# Here we call "release" (or Y-Stream) the first appearance of X.Y.0 version.
Release = namedtuple("Release", ["major", "minor"])

# Default value of N, the number of previous releases to look up.
# The current release cadence is 9 weeks (sometimes extended but not reduced), i.e. 9*7=63 days.
# The current support period is 6 months, i.e. at most 184 days.
# Therefore, at most 3 releases will be in support at any given moment of time with the current cadence and support
# period.
num_releases_default = 3


def main(argv):
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    n = int(argv[1]) if len(argv) > 1 else num_releases_default
    helm_versions = get_latest_helm_chart_versions("stackrox-secured-cluster-services", n)
    logging.info(f"Helm chart versions for the latest {n} releases:")
    print("\n".join(helm_versions))


def get_latest_helm_chart_versions(chart_name, num_releases=num_releases_default):
    add_helm_repo()
    try:
        update_helm_repo()
        return __get_latest_helm_chart_versions(chart_name, num_releases)
    finally:
        remove_helm_repo()


def __get_latest_helm_chart_versions(chart_name, num_releases):
    charts = read_charts()
    logging.info(f"Discovered total {len(charts)} charts")

    filtered_charts = filter_charts_by_name(charts, chart_name)
    logging.info(f"Found {len(filtered_charts)} charts with the given name {chart_name}")

    latest_charts = get_latest_chart_for_each_release(filtered_charts)[:num_releases]
    logging.debug(f"Identified these charts as {num_releases} latest: {latest_charts}")

    return [c["version"] for c in latest_charts]


def read_charts():
    json_str = run_command(search_cmd, log_stdout=False)
    charts_from_json = json.loads(json_str)

    release_charts = [c for c in charts_from_json if is_release_version(c["app_version"])]

    for entry in release_charts:
        entry["parsed_app_version"] = parse_version(entry["app_version"])

    return release_charts


def is_release_version(version):
    return re.search(r"^\d+\.\d+\.\d+$", version) is not None


def parse_version(version_str):
    nums = [int(s) for s in version_str.split(".")]
    return Version(major=nums[0], minor=nums[1], patch=nums[2])


def filter_charts_by_name(charts, chart_name):
    return [c for c in charts if c["name"] == f"{helm_repo_name}/{chart_name}"]


def get_latest_chart_for_each_release(charts):
    sorted_charts = sorted(charts, key=lambda x: x["parsed_app_version"], reverse=True)

    result = []
    release = None

    for chart in sorted_charts:
        chart_release = version_to_release(chart["parsed_app_version"])
        if chart_release != release:
            result.append(chart)
            release = chart_release

    return result


def version_to_release(version):
    return Release(major=version.major, minor=version.minor)


def add_helm_repo():
    logging.info("Adding temp helm repository...")
    run_command(add_repo_cmd)


def update_helm_repo():
    logging.info("Updating temp helm repository...")
    run_command(update_repo_cmd)


def remove_helm_repo():
    logging.info("Removing temp helm repository...")
    run_command(remove_repo_cmd)


def run_command(command, log_stdout=True):
    result = subprocess.run(command, shell=True, encoding='utf-8',
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    stdout = format_command_output("Stdout", result.stdout) if log_stdout else ""
    stderr = format_command_output("Stderr", result.stderr)
    logging.debug(f"Got exit code {result.returncode} for command: {command}{stdout}{stderr}")

    result.check_returncode()

    return result.stdout


def format_command_output(name, output):
    out_no_trailing_newline = output.rstrip()
    if not out_no_trailing_newline:
        return ""
    prefix = "\n" if len(out_no_trailing_newline.splitlines()) > 1 else " "
    return f"\n{name}:{prefix}{out_no_trailing_newline}"


if __name__ == "__main__":
    main(sys.argv)
