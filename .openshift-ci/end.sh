#!/usr/bin/env bash

# The final script executed for openshift/release CI jobs.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
# shellcheck source=../scripts/ci/lib.sh
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

end() {
    info "End of CI handling"

    if [[ -f "${SHARED_DIR:-}/shared_env" ]]; then
        # shellcheck disable=SC1091
        cat "${SHARED_DIR:-}"/shared_env
        source "${SHARED_DIR:-}/shared_env"
    fi

    openshift_ci_mods
    openshift_ci_import_creds

    determine_an_overall_job_outcome

    generate_cluster_junit

    save_job_record "${JOB_NAME:-missing}" "prow" \
        outcome "${OVERALL_JOB_OUTCOME}" \
        started_at "${started_at:-0}" \
        test_target "${test_target:-NULL}" \
        cut_product_version "${cut_product_version:-NULL}" \
        cut_k8s_version "${cut_k8s_version:-NULL}" \
        cut_os_image "${cut_os_image:-NULL}" \
        cut_kernel_version "${cut_kernel_version:-NULL}" \
        cut_container_runtime_version "${cut_container_runtime_version:-NULL}"

    post_process_test_results "${END_SLACK_FAILURE_ATTACHMENTS}" "${END_JUNIT2JIRA_SUMMARY_FILE}"

    if [[ "${OVERALL_JOB_OUTCOME}" == "${OUTCOME_FAILED}" ]]; then
        (send_slack_failure_summary) || { echo >&2 "ERROR: Could not slack a test failure message"; }
    fi
}

determine_an_overall_job_outcome() {
    # Determine a useful overall job outcome based on outcomes shared from prior
    # steps. A default outcome of canceled is assumed for a step with an
    # undefined value. This handles steps that are canceled by openshift-ci and
    # that do not terminate within the termination grace period. In these cases
    # SHARED_DIR state is not propagated.

    combined="${CREATE_CLUSTER_OUTCOME:-${OUTCOME_CANCELED}}-${JOB_DISPATCH_OUTCOME:-${OUTCOME_CANCELED}}-${DESTROY_CLUSTER_OUTCOME:-${OUTCOME_CANCELED}}"

    info "Determining a job outcome from (cluster create-job-cluster destroy):"
    info "${combined}"

    case "${combined}" in
        "${OUTCOME_CANCELED}"-*-*)
            # The job was interrupted before cluster create could complete.
            # Cluster destroy might still pass, fail or be canceled.
            outcome="${OUTCOME_CANCELED}"
            ;;
        "${OUTCOME_FAILED}"-*-*)
            # Track cluster create failures
            outcome="${OUTCOME_FAILED}"
            ;;
        "${OUTCOME_PASSED}-${OUTCOME_CANCELED}"-*)
            # The job was interrupted before the test could complete.
            outcome="${OUTCOME_CANCELED}"
            ;;
        "${OUTCOME_PASSED}-${OUTCOME_FAILED}"-*)
            outcome="${OUTCOME_FAILED}"
            ;;
        "${OUTCOME_PASSED}-${OUTCOME_PASSED}-${OUTCOME_CANCELED}")
            # The job was interrupted before cluster destroy could complete, this is
            # not ideal but we can rely on janitor to clean up, for actionableness
            # track as a passing job.
            outcome="${OUTCOME_PASSED}"
            ;;
        "${OUTCOME_PASSED}-${OUTCOME_PASSED}-${OUTCOME_FAILED}")
            # Track cluster destroy failures as overall job failures.
            outcome="${OUTCOME_FAILED}"
            ;;
        "${OUTCOME_PASSED}-${OUTCOME_PASSED}-${OUTCOME_PASSED}")
            # Perfect score!
            outcome="${OUTCOME_PASSED}"
            ;;
        *)
            info "ERROR: unexpected state in end.sh: ${combined}"
            outcome="${OUTCOME_FAILED}"
            ;;
    esac

    export OVERALL_JOB_OUTCOME="${outcome}"
    info "Overall job outcome: ${outcome}"
}

_JUNIT_CLUSTER_CLASS="Cluster"
_JUNIT_CLUSTER_CREATE_DESCRIPTION="Create"
_JUNIT_CLUSTER_DESTROY_DESCRIPTION="Destroy"

# generate_cluster_junit() - generate junit records for cluster create & destroy
# pass & fail.
generate_cluster_junit() {
    # Change the presentation for cluster types
    local cluster_flavor_variant="${CLUSTER_FLAVOR_VARIANT:-unknown}"
    if [[ ${#cluster_flavor_variant} -le 5 ]]; then
        # uppercase GKE, ARO, ROSA, etc
        cluster_flavor_variant="${cluster_flavor_variant^^}"
    else
        cluster_flavor_variant="${cluster_flavor_variant/openshift/OpenShift}"
    fi

    local cluster_create_debug=""
    if [[ -f "${SHARED_DIR}/cluster_create_failure_debug.txt" ]]; then
        cluster_create_debug="$(summarize_cluster_debug "${SHARED_DIR}/cluster_create_failure_debug.txt")"
    else
        cluster_create_debug="See build.log and Artifacts for details"
    fi

    if [[ "${CREATE_CLUSTER_OUTCOME:-}" == "${OUTCOME_PASSED}" ]]; then
        save_junit_success "${_JUNIT_CLUSTER_CLASS}" "${_JUNIT_CLUSTER_CREATE_DESCRIPTION} ${cluster_flavor_variant}"
    elif [[ "${CREATE_CLUSTER_OUTCOME:-}" == "${OUTCOME_FAILED}" ]]; then
        save_junit_failure "${_JUNIT_CLUSTER_CLASS}" "${_JUNIT_CLUSTER_CREATE_DESCRIPTION} ${cluster_flavor_variant}" \
            "${cluster_create_debug}"
    fi

    local cluster_destroy_debug=""
    if [[ -f "${SHARED_DIR}/cluster_destroy_failure_debug.txt" ]]; then
        cluster_destroy_debug="$(summarize_cluster_debug "${SHARED_DIR}/cluster_destroy_failure_debug.txt")"
    else
        cluster_destroy_debug="See build.log and Artifacts for details"
    fi

    if [[ "${DESTROY_CLUSTER_OUTCOME:-}" == "${OUTCOME_PASSED}" ]]; then
        save_junit_success "${_JUNIT_CLUSTER_CLASS}" "${_JUNIT_CLUSTER_DESTROY_DESCRIPTION} ${cluster_flavor_variant}"
    elif [[ "${DESTROY_CLUSTER_OUTCOME:-}" == "${OUTCOME_FAILED}" && "${CREATE_CLUSTER_OUTCOME:-}" == "${OUTCOME_PASSED}" ]]; then
        # Only record cluster destroy failures when the create succeeded. Otherwise it is mostly noise.
        save_junit_failure "${_JUNIT_CLUSTER_CLASS}" "${_JUNIT_CLUSTER_DESTROY_DESCRIPTION} ${cluster_flavor_variant}" \
            "${cluster_destroy_debug}"
    fi
}

_NUM_LINES_OF_INTEREST=10

summarize_cluster_debug() {
    file="$1"

    last_lines="$(tail --lines="${_NUM_LINES_OF_INTEREST}" "${file}")"
    if [[ -z "${last_lines}" ]]; then
        last_lines="No debug output found."
    fi

    regex='error|warn|fatal|fail'
    suspicious_lines="$(grep -E "${regex}" "${file}" | tail --lines="${_NUM_LINES_OF_INTEREST}")"
    if [[ -z "${suspicious_lines}" ]]; then
        suspicious_lines="None"
    fi

    cat <<_EO_DEBUG_
Last ${_NUM_LINES_OF_INTEREST} lines from output:
====
${last_lines}

Lines matching ${regex} (last ${_NUM_LINES_OF_INTEREST}):
====
${suspicious_lines}
_EO_DEBUG_
}

end
