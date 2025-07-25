import React from 'react';
import { Trash2 } from 'react-feather';

import RowActionButton from 'Components/RowActionButton';
import {
    defaultHeaderClassName,
    defaultColumnClassName,
    wrapClassName,
    rtTrActionsClassName,
} from 'Components/Table';

import { formatCloudProvider } from './cluster.helpers';
import ClusterDeletion from './Components/ClusterDeletion';
import ClusterNameWithTypeIcon from './Components/ClusterNameWithTypeIcon';
import ClusterStatusLegacy from './Components/ClusterStatusLegacy';
import CredentialExpiration from './Components/CredentialExpiration';
import SensorUpgradeLegacy from './Components/SensorUpgradeLegacy';

export function getColumnsForClusters({
    clusterIdToRetentionInfo,
    hasWriteAccessForCluster,
    metadata,
    rowActions,
}) {
    function renderRowActionButtons(cluster) {
        return (
            <div className="border-2 border-r-2 border-base-400 bg-base-100">
                <RowActionButton
                    text="Delete cluster"
                    icon={<Trash2 className="my-1 h-4 w-4" />}
                    className="pf-v5-u-danger-color-100"
                    onClick={rowActions.onDeleteHandler(cluster)}
                />
            </div>
        );
    }

    // Because of fixed checkbox width, total of column ratios must be less than 1
    // 5/7 + 1/4 = 0.964
    const clusterColumns = [
        {
            accessor: 'name',
            Header: 'Name',
            headerClassName: `w-1/7 ${defaultHeaderClassName}`,
            className: `w-1/7 ${wrapClassName} ${defaultColumnClassName}`,
            Cell: ({ original }) => <ClusterNameWithTypeIcon cluster={original} />,
        },
        {
            Header: 'Cloud Provider',
            Cell: ({ original }) => formatCloudProvider(original.status?.providerMetadata),
            headerClassName: `w-1/7 ${defaultHeaderClassName}`,
            className: `w-1/7 ${wrapClassName} ${defaultColumnClassName}`,
            sortable: false,
        },
        {
            Header: 'Cluster Status',
            Cell: ({ original }) => {
                const safeHealthStatus = original.healthStatus || {
                    overallHealthStatus: 'UNINITIALIZED',
                };
                return <ClusterStatusLegacy healthStatus={safeHealthStatus} isList />;
            },
            headerClassName: `w-1/4 ${defaultHeaderClassName}`,
            className: `w-1/4 ${wrapClassName} ${defaultColumnClassName}`,
            sortable: false,
        },
        {
            Header: 'Sensor Upgrade',
            Cell: ({ original }) => (
                <SensorUpgradeLegacy
                    upgradeStatus={original.status?.upgradeStatus}
                    centralVersion={metadata.version}
                    sensorVersion={original.status?.sensorVersion}
                    isList
                    actionProps={{
                        clusterId: original.id,
                        upgradeSingleCluster: rowActions.upgradeSingleCluster,
                    }}
                />
            ),
            headerClassName: `w-1/7 ${defaultHeaderClassName}`,
            className: `w-1/7 ${wrapClassName} ${defaultColumnClassName}`,
            sortable: false,
        },
        {
            Header: 'Credential Expiration',
            Cell: ({ original }) => (
                <CredentialExpiration
                    certExpiryStatus={original.status?.certExpiryStatus}
                    autoRefreshEnabled={original.sensorCapabilities?.includes(
                        'SecuredClusterCertificatesRefresh'
                    )}
                    currentDatetime={new Date()}
                    isList
                />
            ),
            headerClassName: `w-1/7 ${defaultHeaderClassName}`,
            className: `w-1/7 ${wrapClassName} ${defaultColumnClassName}`,
            sortable: false,
        },
        {
            Header: 'Cluster Deletion',
            Cell: ({ original }) => (
                <ClusterDeletion
                    clusterRetentionInfo={clusterIdToRetentionInfo[original.id] ?? null}
                />
            ),
            headerClassName: `w-1/7 ${defaultHeaderClassName}`,
            className: `w-1/7 ${wrapClassName} ${defaultColumnClassName}`,
            sortable: false,
        },
    ];

    if (hasWriteAccessForCluster) {
        clusterColumns.push({
            Header: '',
            accessor: '',
            headerClassName: 'hidden',
            className: rtTrActionsClassName,
            Cell: ({ original }) => renderRowActionButtons(original),
        });
    }

    return clusterColumns;
}

export default {
    getColumnsForClusters,
};
