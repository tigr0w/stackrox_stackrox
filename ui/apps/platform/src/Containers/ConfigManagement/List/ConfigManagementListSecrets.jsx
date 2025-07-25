import React from 'react';
import { useLocation } from 'react-router-dom-v5-compat';
import uniq from 'lodash/uniq';
import pluralize from 'pluralize';

import {
    defaultHeaderClassName,
    defaultColumnClassName,
    nonSortableHeaderClassName,
} from 'Components/Table';
import TableCellLink from 'Components/TableCellLink';
import { entityListPropTypes, entityListDefaultprops } from 'constants/entityPageProps';
import useWorkflowMatch from 'hooks/useWorkflowMatch';
import { SECRETS_QUERY } from 'queries/secret';
import { secretSortFields } from 'constants/sortFields';
import { getDateTime } from 'utils/dateUtils';
import queryService from 'utils/queryService';
import URLService from 'utils/URLService';
import { getConfigMgmtPathForEntitiesAndId } from '../entities';
import List from './List';

const secretTypeEnumMapping = {
    UNDETERMINED: 'Undetermined',
    PUBLIC_CERTIFICATE: 'Public Certificate',
    CERTIFICATE_REQUEST: 'Certificate Request',
    PRIVACY_ENHANCED_MESSAGE: 'Privacy Enhanced Message',
    OPENSSH_PRIVATE_KEY: 'OpenSSH Private Key',
    PGP_PRIVATE_KEY: 'PGP Private Key',
    EC_PRIVATE_KEY: 'EC Private Key',
    RSA_PRIVATE_KEY: 'RSA Private Key',
    DSA_PRIVATE_KEY: 'DSA Private Key',
    CERT_PRIVATE_KEY: 'Certificate Private Key',
    ENCRYPTED_PRIVATE_KEY: 'Encrypted Private Key',
    IMAGE_PULL_SECRET: 'Image Pull Secret',
};

export const defaultSecretSort = [
    {
        id: secretSortFields.SECRET,
        desc: false,
    },
];

const buildTableColumns = (match, location, entityContext) => {
    const tableColumns = [
        {
            Header: 'Id',
            headerClassName: 'hidden',
            className: 'hidden',
            accessor: 'id',
        },
        {
            Header: `Secret`,
            headerClassName: `w-1/8 ${defaultHeaderClassName}`,
            className: `w-1/8 ${defaultColumnClassName}`,
            Cell: ({ original, pdf }) => {
                const url = getConfigMgmtPathForEntitiesAndId('SECRET', original.id);
                return (
                    <TableCellLink pdf={pdf} url={url}>
                        {original.name}
                    </TableCellLink>
                );
            },
            accessor: 'name',
            id: secretSortFields.SECRET,
            sortField: secretSortFields.SECRET,
        },
        {
            Header: `Created`,
            headerClassName: `w-1/8 ${defaultHeaderClassName}`,
            className: `w-1/8 ${defaultColumnClassName}`,
            Cell: ({ original }) => {
                const { createdAt } = original;
                return getDateTime(createdAt);
            },
            accessor: 'createdAt',
            id: secretSortFields.CREATED,
            sortField: secretSortFields.CREATED,
        },
        {
            Header: `Types`,
            headerClassName: `w-1/8 ${nonSortableHeaderClassName}`,
            className: `w-1/8 ${defaultColumnClassName}`,
            accessor: 'files',
            Cell: ({ original }) => {
                const { files } = original;
                if (!files.length) {
                    return 'No Types';
                }
                return (
                    <span>
                        {uniq(files.map((file) => secretTypeEnumMapping[file.type])).join(', ')}
                    </span>
                );
            },
            sortable: false,
        },
        entityContext && entityContext.CLUSTER
            ? null
            : {
                  Header: `Cluster`,
                  headerClassName: `w-1/8 ${defaultHeaderClassName}`,
                  className: `w-1/8 ${defaultColumnClassName}`,
                  accessor: 'clusterName',
                  Cell: ({ original, pdf }) => {
                      const { clusterName, clusterId, id } = original;
                      const url = URLService.getURL(match, location)
                          .push(id)
                          .push('CLUSTER', clusterId)
                          .url();
                      return (
                          <TableCellLink pdf={pdf} url={url}>
                              {clusterName}
                          </TableCellLink>
                      );
                  },
                  id: secretSortFields.CLUSTER,
                  sortField: secretSortFields.CLUSTER,
              },
        {
            Header: `Deployments`,
            headerClassName: `w-1/8 ${nonSortableHeaderClassName}`,
            className: `w-1/8 ${defaultColumnClassName}`,
            accessor: 'deployments',
            Cell: ({ original, pdf }) => {
                const { deploymentCount, id } = original;
                if (!deploymentCount) {
                    return 'No Deployments';
                }
                const url = URLService.getURL(match, location).push(id).push('DEPLOYMENT').url();
                const text = `${deploymentCount} ${pluralize('Deployment', deploymentCount)}`;
                return (
                    <TableCellLink pdf={pdf} url={url}>
                        {text}
                    </TableCellLink>
                );
            },
            sortable: false,
        },
    ];
    return tableColumns.filter((col) => col);
};

const createTableRows = (data) => {
    return data.secrets;
};

const ConfigManagementListSecrets = ({
    className,
    selectedRowId,
    onRowClick,
    query,
    data,
    totalResults,
    entityContext,
}) => {
    const location = useLocation();
    const match = useWorkflowMatch();
    const autoFocusSearchInput = !selectedRowId;
    const tableColumns = buildTableColumns(match, location, entityContext);
    const queryText = queryService.objectToWhereClause(query);
    const variables = queryText ? { query: queryText } : null;
    return (
        <List
            className={className}
            query={SECRETS_QUERY}
            variables={variables}
            entityType="SECRET"
            tableColumns={tableColumns}
            createTableRows={createTableRows}
            onRowClick={onRowClick}
            selectedRowId={selectedRowId}
            idAttribute="id"
            defaultSorted={defaultSecretSort}
            data={data}
            totalResults={totalResults}
            autoFocusSearchInput={autoFocusSearchInput}
        />
    );
};
ConfigManagementListSecrets.propTypes = entityListPropTypes;
ConfigManagementListSecrets.defaultProps = entityListDefaultprops;

export default ConfigManagementListSecrets;
