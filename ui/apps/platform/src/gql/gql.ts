/* eslint-disable */
import * as types from './graphql';
import { TypedDocumentNode as DocumentNode } from '@graphql-typed-document-node/core';

/**
 * Map of all GraphQL operations in the project.
 *
 * This map has several performance disadvantages:
 * 1. It is not tree-shakeable, so it will include all operations in the project.
 * 2. It is not minifiable, so the string of a GraphQL query will be multiple times inside the bundle.
 * 3. It does not support dead code elimination, so it will add unused operations.
 *
 * Therefore it is highly recommended to use the babel or swc plugin for production.
 */
const documents = {
    '\n    query getAllNamespacesByCluster($query: String) {\n        clusters(query: $query) {\n            id\n            name\n            namespaces {\n                metadata {\n                    id\n                    name\n                }\n            }\n        }\n    }\n':
        types.GetAllNamespacesByClusterDocument,
    '\n    query summary_counts {\n        clusterCount\n        nodeCount\n        violationCount\n        deploymentCount\n        imageCount\n        secretCount\n    }\n':
        types.Summary_CountsDocument,
    '\n    query agingImagesQuery($query0: String, $query1: String, $query2: String, $query3: String) {\n        timeRange0: imageCount(query: $query0)\n        timeRange1: imageCount(query: $query1)\n        timeRange2: imageCount(query: $query2)\n        timeRange3: imageCount(query: $query3)\n    }\n':
        types.AgingImagesQueryDocument,
    '\n              query getImagesAtMostRisk($query: String) {\n                  images(\n                      query: $query\n                      pagination: {\n                          limit: 6\n                          sortOption: { field: "Image Risk Priority", reversed: false }\n                      }\n                  ) {\n                      id\n                      name {\n                          remote\n                          fullName\n                      }\n                      priority\n                      imageVulnerabilityCounter {\n                          important {\n                              total\n                              fixable\n                          }\n                          critical {\n                              total\n                              fixable\n                          }\n                      }\n                  }\n              }\n          ':
        types.GetImagesAtMostRiskDocument,
    '\n              query getImagesAtMostRiskLegacy($query: String) {\n                  images(\n                      query: $query\n                      pagination: {\n                          limit: 6\n                          sortOption: { field: "Image Risk Priority", reversed: false }\n                      }\n                  ) {\n                      id\n                      name {\n                          remote\n                          fullName\n                      }\n                      priority\n                      imageVulnerabilityCounter: vulnCounter {\n                          important {\n                              total\n                              fixable\n                          }\n                          critical {\n                              total\n                              fixable\n                          }\n                      }\n                  }\n              }\n          ':
        types.GetImagesAtMostRiskLegacyDocument,
    '\n    query healths($query: String) {\n        results: clusterHealthCounter(query: $query) {\n            total\n            uninitialized\n            healthy\n            degraded\n            unhealthy\n        }\n    }\n':
        types.HealthsDocument,
    '\n    query cluster_summary_counts {\n        clusterCount\n    }\n':
        types.Cluster_Summary_CountsDocument,
    '\n    query getMitreAttackVectors($id: ID!) {\n        policy(id: $id) {\n            mitreAttackVectors: fullMitreAttackVectors {\n                tactic {\n                    id\n                    name\n                    description\n                }\n                techniques {\n                    id\n                    name\n                    description\n                }\n            }\n        }\n    }\n':
        types.GetMitreAttackVectorsDocument,
    '\n    query getImageVulnerabilities($imageId: ID!, $vulnsQuery: String, $pagination: Pagination) {\n        image(id: $imageId) {\n            name {\n                registry\n                remote\n                tag\n            }\n            vulnCount: imageVulnerabilityCount(query: $vulnsQuery)\n            vulns: imageVulnerabilities(query: $vulnsQuery, pagination: $pagination) {\n                id\n                cve\n                isFixable\n                severity\n                scoreVersion\n                cvss\n                discoveredAtImage\n                components: imageComponents {\n                    id\n                    name\n                    version\n                    fixedIn\n                }\n                vulnerabilityRequest: effectiveVulnerabilityRequest {\n                    id\n                    targetState\n                    status\n                    expired\n                    requestor {\n                        id\n                        name\n                    }\n                    approvers {\n                        id\n                        name\n                    }\n                    comments {\n                        createdAt\n                        id\n                        message\n                        user {\n                            id\n                            name\n                        }\n                    }\n                    deferralReq {\n                        expiresOn\n                        expiresWhenFixed\n                    }\n                    updatedDeferralReq {\n                        expiresOn\n                        expiresWhenFixed\n                    }\n                    scope {\n                        imageScope {\n                            registry\n                            remote\n                            tag\n                        }\n                    }\n                    cves {\n                        cves\n                    }\n                }\n            }\n        }\n    }\n':
        types.GetImageVulnerabilitiesDocument,
    '\n    query getImageVulnerabilitiesLegacy(\n        $imageId: ID!\n        $vulnsQuery: String\n        $pagination: Pagination\n    ) {\n        image(id: $imageId) {\n            name {\n                registry\n                remote\n                tag\n            }\n            vulnCount(query: $vulnsQuery)\n            vulns(query: $vulnsQuery, pagination: $pagination) {\n                id\n                cve\n                isFixable\n                severity\n                scoreVersion\n                cvss\n                discoveredAtImage\n                components {\n                    id\n                    name\n                    version\n                    fixedIn\n                }\n                vulnerabilityRequest: effectiveVulnerabilityRequest {\n                    id\n                    targetState\n                    status\n                    expired\n                    requestor {\n                        id\n                        name\n                    }\n                    approvers {\n                        id\n                        name\n                    }\n                    comments {\n                        createdAt\n                        id\n                        message\n                        user {\n                            id\n                            name\n                        }\n                    }\n                    deferralReq {\n                        expiresOn\n                        expiresWhenFixed\n                    }\n                    updatedDeferralReq {\n                        expiresOn\n                        expiresWhenFixed\n                    }\n                    scope {\n                        imageScope {\n                            registry\n                            remote\n                            tag\n                        }\n                    }\n                    cves {\n                        cves\n                    }\n                }\n            }\n        }\n    }\n':
        types.GetImageVulnerabilitiesLegacyDocument,
    '\n    mutation deferVulnerability($request: DeferVulnRequest!) {\n        deferVulnerability(request: $request) {\n            id\n        }\n    }\n':
        types.DeferVulnerabilityDocument,
    '\n    mutation markVulnerabilityFalsePositive($request: FalsePositiveVulnRequest!) {\n        markVulnerabilityFalsePositive(request: $request) {\n            id\n        }\n    }\n':
        types.MarkVulnerabilityFalsePositiveDocument,
    '\n    query getVulnerabilityRequests(\n        $query: String\n        $requestIDSelector: String\n        $pagination: Pagination\n    ) {\n        vulnerabilityRequests(\n            query: $query\n            requestIDSelector: $requestIDSelector\n            pagination: $pagination\n        ) {\n            id\n            targetState\n            status\n            requestor {\n                id\n                name\n            }\n            comments {\n                createdAt\n                id\n                message\n                user {\n                    id\n                    name\n                }\n            }\n            scope {\n                imageScope {\n                    registry\n                    remote\n                    tag\n                }\n            }\n            deferralReq {\n                expiresOn\n                expiresWhenFixed\n            }\n            updatedDeferralReq {\n                expiresOn\n                expiresWhenFixed\n            }\n            cves {\n                cves\n            }\n            deployments(query: $query) {\n                id\n                name\n                namespace\n                clusterName\n            }\n            deploymentCount(query: $query)\n            images(query: $query) {\n                id\n                name {\n                    fullName\n                }\n            }\n            imageCount(query: $query)\n        }\n        vulnerabilityRequestsCount(query: $query)\n    }\n':
        types.GetVulnerabilityRequestsDocument,
    '\n    mutation approveVulnerabilityRequest($requestID: ID!, $comment: String!) {\n        approveVulnerabilityRequest(requestID: $requestID, comment: $comment) {\n            id\n        }\n    }\n':
        types.ApproveVulnerabilityRequestDocument,
    '\n    mutation denyVulnerabilityRequest($requestID: ID!, $comment: String!) {\n        denyVulnerabilityRequest(requestID: $requestID, comment: $comment) {\n            id\n        }\n    }\n':
        types.DenyVulnerabilityRequestDocument,
    '\n    mutation deleteVulnerabilityRequest($requestID: ID!) {\n        deleteVulnerabilityRequest(requestID: $requestID)\n    }\n':
        types.DeleteVulnerabilityRequestDocument,
    '\n    mutation undoVulnerabilityRequest($requestID: ID!) {\n        undoVulnerabilityRequest(requestID: $requestID) {\n            id\n        }\n    }\n':
        types.UndoVulnerabilityRequestDocument,
    '\n    mutation updateVulnerabilityRequest(\n        $requestID: ID!\n        $comment: String!\n        $expiry: VulnReqExpiry!\n    ) {\n        updateVulnerabilityRequest(requestID: $requestID, comment: $comment, expiry: $expiry) {\n            id\n        }\n    }\n':
        types.UpdateVulnerabilityRequestDocument,
    '\n    query getImageDetails($id: ID!) {\n        image(id: $id) {\n            id\n            name {\n                registry\n                remote\n                tag\n            }\n            ...ImageDetails\n        }\n    }\n':
        types.GetImageDetailsDocument,
    '\n    \n    \n    \n    query getImageCoreVulnerabilities($id: ID!, $query: String!, $pagination: Pagination!) {\n        image(id: $id) {\n            ...ImageMetadataContext\n            imageCVECountBySeverity(query: $query) {\n                ...AllResourceCountsByCVESeverity\n            }\n            imageVulnerabilities(query: $query, pagination: $pagination) {\n                ...ImageVulnerabilityFields\n            }\n        }\n    }\n':
        types.GetImageCoreVulnerabilitiesDocument,
    '\n    \n    query getImageCveMetadata($cve: String!) {\n        imageCVE(cve: $cve) {\n            ...ImageCVEMetadata\n        }\n    }\n':
        types.GetImageCveMetadataDocument,
    '\n    \n    \n    query getImageCveSummaryData($cve: String!, $query: String!) {\n        ...ImageCVESummaryCounts\n        imageCount(query: $query)\n        deploymentCount(query: $query)\n        imageCVE(cve: $cve, subfieldScopeQuery: $query) {\n            cve\n            ...ImageCVESeveritySummary\n        }\n    }\n':
        types.GetImageCveSummaryDataDocument,
    '\n    \n    # by default, query must include the CVE id\n    query getImagesForCVE($query: String, $pagination: Pagination) {\n        images(query: $query, pagination: $pagination) {\n            ...ImagesForCVE\n        }\n    }\n':
        types.GetImagesForCveDocument,
    '\n    \n    # by default, query must include the CVE id\n    query getDeploymentsForCVE($query: String, $pagination: Pagination) {\n        deployments(query: $query, pagination: $pagination) {\n            ...DeploymentsForCVE\n        }\n    }\n':
        types.GetDeploymentsForCveDocument,
    '\n    fragment ImageCVEMetadata on ImageCVECore {\n        cve\n        # TODO summary\n        # TODO url\n        firstDiscoveredInSystem\n    }\n':
        types.ImageCveMetadataFragmentDoc,
    '\n    fragment ImageCVESeveritySummary on ImageCVECore {\n        affectedImageCountBySeverity {\n            critical {\n                total\n            }\n            important {\n                total\n            }\n            moderate {\n                total\n            }\n            low {\n                total\n            }\n        }\n        affectedImageCount\n        topCVSS\n        # TODO vector\n    }\n':
        types.ImageCveSeveritySummaryFragmentDoc,
    '\n    fragment ImageCVESummaryCounts on Query {\n        totalImageCount: imageCount\n    }\n':
        types.ImageCveSummaryCountsFragmentDoc,
    '\n    query getEntityTypeCounts($query: String) {\n        imageCount(query: $query)\n        deploymentCount(query: $query)\n        imageCVECount(query: $query)\n    }\n':
        types.GetEntityTypeCountsDocument,
    '\n    fragment AllResourceCountsByCVESeverity on ResourceCountByCVESeverity {\n        low {\n            total\n            fixable\n        }\n        moderate {\n            total\n            fixable\n        }\n        important {\n            total\n            fixable\n        }\n        critical {\n            total\n            fixable\n        }\n    }\n':
        types.AllResourceCountsByCveSeverityFragmentDoc,
    '\n    \n    \n    fragment DeploymentsForCVE on Deployment {\n        id\n        name\n        namespace\n        clusterName\n        created\n        imageCount(query: $query)\n        images(query: $query) {\n            ...ImageMetadataContext\n            imageComponents(query: $query) {\n                ...ComponentVulnerabilities\n            }\n        }\n    }\n':
        types.DeploymentsForCveFragmentDoc,
    '\n    \n    \n    fragment ImagesForCVE on Image {\n        ...ImageMetadataContext\n\n        operatingSystem\n        watchStatus\n        scanTime\n\n        imageComponents(query: $query) {\n            ...ComponentVulnerabilities\n        }\n    }\n':
        types.ImagesForCveFragmentDoc,
    '\n    query getImageCVEList($query: String, $pagination: Pagination) {\n        imageCVEs(query: $query, pagination: $pagination) {\n            cve\n            affectedImageCountBySeverity {\n                critical {\n                    total\n                }\n                important {\n                    total\n                }\n                moderate {\n                    total\n                }\n                low {\n                    total\n                }\n            }\n            topCVSS\n            affectedImageCount\n            firstDiscoveredInSystem\n        }\n    }\n':
        types.GetImageCveListDocument,
    '\n    query getUnfilteredImageCount {\n        imageCount\n    }\n':
        types.GetUnfilteredImageCountDocument,
    '\n    fragment ImageMetadataContext on Image {\n        id\n        name {\n            registry\n            remote\n            tag\n        }\n        metadata {\n            v1 {\n                layers {\n                    instruction\n                    value\n                }\n            }\n        }\n    }\n':
        types.ImageMetadataContextFragmentDoc,
    '\n    fragment ComponentVulnerabilities on ImageComponent {\n        name\n        version\n        location\n        layerIndex\n        imageVulnerabilities(query: $query) {\n            id\n            severity\n            fixedByVersion\n        }\n    }\n':
        types.ComponentVulnerabilitiesFragmentDoc,
    '\n    query getDeploymentList($query: String, $pagination: Pagination) {\n        deployments(query: $query, pagination: $pagination) {\n            id\n            name\n            imageCVECountBySeverity(query: $query) {\n                critical {\n                    total\n                }\n                important {\n                    total\n                }\n                moderate {\n                    total\n                }\n                low {\n                    total\n                }\n            }\n            clusterName\n            namespace\n            imageCount(query: $query)\n            created\n        }\n    }\n':
        types.GetDeploymentListDocument,
    '\n    query getImageList($query: String, $pagination: Pagination) {\n        images(query: $query, pagination: $pagination) {\n            id\n            name {\n                registry\n                remote\n                tag\n            }\n            imageCVECountBySeverity(query: $query) {\n                critical {\n                    total\n                }\n                important {\n                    total\n                }\n                moderate {\n                    total\n                }\n                low {\n                    total\n                }\n            }\n            operatingSystem\n            deploymentCount(query: $query)\n            watchStatus\n            metadata {\n                v1 {\n                    created\n                }\n            }\n            scanTime\n        }\n    }\n':
        types.GetImageListDocument,
    '\n    \n    fragment ImageVulnerabilityFields on ImageVulnerability {\n        id\n        severity\n        isFixable\n        cve\n        summary\n        cvss\n        scoreVersion\n        discoveredAtImage\n        imageComponents(query: $query) {\n            ...ComponentVulnerabilities\n        }\n    }\n':
        types.ImageVulnerabilityFieldsFragmentDoc,
    '\n    fragment ImageDetails on Image {\n        id\n        deploymentCount\n        operatingSystem\n        metadata {\n            v1 {\n                created\n                digest\n            }\n        }\n        dataSource {\n            id\n            name\n        }\n        scanTime\n    }\n':
        types.ImageDetailsFragmentDoc,
    '\n    query deployments($query: String) {\n        count: deploymentCount(query: $query)\n    }\n':
        types.DeploymentsDocument,
    '\n    query getNamespaceDeployments($query: String!) {\n        results: namespaces(query: $query) {\n            metadata {\n                name\n                id\n            }\n            deployments {\n                name\n                id\n            }\n        }\n    }\n':
        types.GetNamespaceDeploymentsDocument,
};

/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 *
 *
 * @example
 * ```ts
 * const query = graphql(`query GetUser($id: ID!) { user(id: $id) { name } }`);
 * ```
 *
 * The query argument is unknown!
 * Please regenerate the types.
 */
export function graphql(source: string): unknown;

/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    query getAllNamespacesByCluster($query: String) {\n        clusters(query: $query) {\n            id\n            name\n            namespaces {\n                metadata {\n                    id\n                    name\n                }\n            }\n        }\n    }\n'
): (typeof documents)['\n    query getAllNamespacesByCluster($query: String) {\n        clusters(query: $query) {\n            id\n            name\n            namespaces {\n                metadata {\n                    id\n                    name\n                }\n            }\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    query summary_counts {\n        clusterCount\n        nodeCount\n        violationCount\n        deploymentCount\n        imageCount\n        secretCount\n    }\n'
): (typeof documents)['\n    query summary_counts {\n        clusterCount\n        nodeCount\n        violationCount\n        deploymentCount\n        imageCount\n        secretCount\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    query agingImagesQuery($query0: String, $query1: String, $query2: String, $query3: String) {\n        timeRange0: imageCount(query: $query0)\n        timeRange1: imageCount(query: $query1)\n        timeRange2: imageCount(query: $query2)\n        timeRange3: imageCount(query: $query3)\n    }\n'
): (typeof documents)['\n    query agingImagesQuery($query0: String, $query1: String, $query2: String, $query3: String) {\n        timeRange0: imageCount(query: $query0)\n        timeRange1: imageCount(query: $query1)\n        timeRange2: imageCount(query: $query2)\n        timeRange3: imageCount(query: $query3)\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n              query getImagesAtMostRisk($query: String) {\n                  images(\n                      query: $query\n                      pagination: {\n                          limit: 6\n                          sortOption: { field: "Image Risk Priority", reversed: false }\n                      }\n                  ) {\n                      id\n                      name {\n                          remote\n                          fullName\n                      }\n                      priority\n                      imageVulnerabilityCounter {\n                          important {\n                              total\n                              fixable\n                          }\n                          critical {\n                              total\n                              fixable\n                          }\n                      }\n                  }\n              }\n          '
): (typeof documents)['\n              query getImagesAtMostRisk($query: String) {\n                  images(\n                      query: $query\n                      pagination: {\n                          limit: 6\n                          sortOption: { field: "Image Risk Priority", reversed: false }\n                      }\n                  ) {\n                      id\n                      name {\n                          remote\n                          fullName\n                      }\n                      priority\n                      imageVulnerabilityCounter {\n                          important {\n                              total\n                              fixable\n                          }\n                          critical {\n                              total\n                              fixable\n                          }\n                      }\n                  }\n              }\n          '];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n              query getImagesAtMostRiskLegacy($query: String) {\n                  images(\n                      query: $query\n                      pagination: {\n                          limit: 6\n                          sortOption: { field: "Image Risk Priority", reversed: false }\n                      }\n                  ) {\n                      id\n                      name {\n                          remote\n                          fullName\n                      }\n                      priority\n                      imageVulnerabilityCounter: vulnCounter {\n                          important {\n                              total\n                              fixable\n                          }\n                          critical {\n                              total\n                              fixable\n                          }\n                      }\n                  }\n              }\n          '
): (typeof documents)['\n              query getImagesAtMostRiskLegacy($query: String) {\n                  images(\n                      query: $query\n                      pagination: {\n                          limit: 6\n                          sortOption: { field: "Image Risk Priority", reversed: false }\n                      }\n                  ) {\n                      id\n                      name {\n                          remote\n                          fullName\n                      }\n                      priority\n                      imageVulnerabilityCounter: vulnCounter {\n                          important {\n                              total\n                              fixable\n                          }\n                          critical {\n                              total\n                              fixable\n                          }\n                      }\n                  }\n              }\n          '];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    query healths($query: String) {\n        results: clusterHealthCounter(query: $query) {\n            total\n            uninitialized\n            healthy\n            degraded\n            unhealthy\n        }\n    }\n'
): (typeof documents)['\n    query healths($query: String) {\n        results: clusterHealthCounter(query: $query) {\n            total\n            uninitialized\n            healthy\n            degraded\n            unhealthy\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    query cluster_summary_counts {\n        clusterCount\n    }\n'
): (typeof documents)['\n    query cluster_summary_counts {\n        clusterCount\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    query getMitreAttackVectors($id: ID!) {\n        policy(id: $id) {\n            mitreAttackVectors: fullMitreAttackVectors {\n                tactic {\n                    id\n                    name\n                    description\n                }\n                techniques {\n                    id\n                    name\n                    description\n                }\n            }\n        }\n    }\n'
): (typeof documents)['\n    query getMitreAttackVectors($id: ID!) {\n        policy(id: $id) {\n            mitreAttackVectors: fullMitreAttackVectors {\n                tactic {\n                    id\n                    name\n                    description\n                }\n                techniques {\n                    id\n                    name\n                    description\n                }\n            }\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    query getImageVulnerabilities($imageId: ID!, $vulnsQuery: String, $pagination: Pagination) {\n        image(id: $imageId) {\n            name {\n                registry\n                remote\n                tag\n            }\n            vulnCount: imageVulnerabilityCount(query: $vulnsQuery)\n            vulns: imageVulnerabilities(query: $vulnsQuery, pagination: $pagination) {\n                id\n                cve\n                isFixable\n                severity\n                scoreVersion\n                cvss\n                discoveredAtImage\n                components: imageComponents {\n                    id\n                    name\n                    version\n                    fixedIn\n                }\n                vulnerabilityRequest: effectiveVulnerabilityRequest {\n                    id\n                    targetState\n                    status\n                    expired\n                    requestor {\n                        id\n                        name\n                    }\n                    approvers {\n                        id\n                        name\n                    }\n                    comments {\n                        createdAt\n                        id\n                        message\n                        user {\n                            id\n                            name\n                        }\n                    }\n                    deferralReq {\n                        expiresOn\n                        expiresWhenFixed\n                    }\n                    updatedDeferralReq {\n                        expiresOn\n                        expiresWhenFixed\n                    }\n                    scope {\n                        imageScope {\n                            registry\n                            remote\n                            tag\n                        }\n                    }\n                    cves {\n                        cves\n                    }\n                }\n            }\n        }\n    }\n'
): (typeof documents)['\n    query getImageVulnerabilities($imageId: ID!, $vulnsQuery: String, $pagination: Pagination) {\n        image(id: $imageId) {\n            name {\n                registry\n                remote\n                tag\n            }\n            vulnCount: imageVulnerabilityCount(query: $vulnsQuery)\n            vulns: imageVulnerabilities(query: $vulnsQuery, pagination: $pagination) {\n                id\n                cve\n                isFixable\n                severity\n                scoreVersion\n                cvss\n                discoveredAtImage\n                components: imageComponents {\n                    id\n                    name\n                    version\n                    fixedIn\n                }\n                vulnerabilityRequest: effectiveVulnerabilityRequest {\n                    id\n                    targetState\n                    status\n                    expired\n                    requestor {\n                        id\n                        name\n                    }\n                    approvers {\n                        id\n                        name\n                    }\n                    comments {\n                        createdAt\n                        id\n                        message\n                        user {\n                            id\n                            name\n                        }\n                    }\n                    deferralReq {\n                        expiresOn\n                        expiresWhenFixed\n                    }\n                    updatedDeferralReq {\n                        expiresOn\n                        expiresWhenFixed\n                    }\n                    scope {\n                        imageScope {\n                            registry\n                            remote\n                            tag\n                        }\n                    }\n                    cves {\n                        cves\n                    }\n                }\n            }\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    query getImageVulnerabilitiesLegacy(\n        $imageId: ID!\n        $vulnsQuery: String\n        $pagination: Pagination\n    ) {\n        image(id: $imageId) {\n            name {\n                registry\n                remote\n                tag\n            }\n            vulnCount(query: $vulnsQuery)\n            vulns(query: $vulnsQuery, pagination: $pagination) {\n                id\n                cve\n                isFixable\n                severity\n                scoreVersion\n                cvss\n                discoveredAtImage\n                components {\n                    id\n                    name\n                    version\n                    fixedIn\n                }\n                vulnerabilityRequest: effectiveVulnerabilityRequest {\n                    id\n                    targetState\n                    status\n                    expired\n                    requestor {\n                        id\n                        name\n                    }\n                    approvers {\n                        id\n                        name\n                    }\n                    comments {\n                        createdAt\n                        id\n                        message\n                        user {\n                            id\n                            name\n                        }\n                    }\n                    deferralReq {\n                        expiresOn\n                        expiresWhenFixed\n                    }\n                    updatedDeferralReq {\n                        expiresOn\n                        expiresWhenFixed\n                    }\n                    scope {\n                        imageScope {\n                            registry\n                            remote\n                            tag\n                        }\n                    }\n                    cves {\n                        cves\n                    }\n                }\n            }\n        }\n    }\n'
): (typeof documents)['\n    query getImageVulnerabilitiesLegacy(\n        $imageId: ID!\n        $vulnsQuery: String\n        $pagination: Pagination\n    ) {\n        image(id: $imageId) {\n            name {\n                registry\n                remote\n                tag\n            }\n            vulnCount(query: $vulnsQuery)\n            vulns(query: $vulnsQuery, pagination: $pagination) {\n                id\n                cve\n                isFixable\n                severity\n                scoreVersion\n                cvss\n                discoveredAtImage\n                components {\n                    id\n                    name\n                    version\n                    fixedIn\n                }\n                vulnerabilityRequest: effectiveVulnerabilityRequest {\n                    id\n                    targetState\n                    status\n                    expired\n                    requestor {\n                        id\n                        name\n                    }\n                    approvers {\n                        id\n                        name\n                    }\n                    comments {\n                        createdAt\n                        id\n                        message\n                        user {\n                            id\n                            name\n                        }\n                    }\n                    deferralReq {\n                        expiresOn\n                        expiresWhenFixed\n                    }\n                    updatedDeferralReq {\n                        expiresOn\n                        expiresWhenFixed\n                    }\n                    scope {\n                        imageScope {\n                            registry\n                            remote\n                            tag\n                        }\n                    }\n                    cves {\n                        cves\n                    }\n                }\n            }\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    mutation deferVulnerability($request: DeferVulnRequest!) {\n        deferVulnerability(request: $request) {\n            id\n        }\n    }\n'
): (typeof documents)['\n    mutation deferVulnerability($request: DeferVulnRequest!) {\n        deferVulnerability(request: $request) {\n            id\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    mutation markVulnerabilityFalsePositive($request: FalsePositiveVulnRequest!) {\n        markVulnerabilityFalsePositive(request: $request) {\n            id\n        }\n    }\n'
): (typeof documents)['\n    mutation markVulnerabilityFalsePositive($request: FalsePositiveVulnRequest!) {\n        markVulnerabilityFalsePositive(request: $request) {\n            id\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    query getVulnerabilityRequests(\n        $query: String\n        $requestIDSelector: String\n        $pagination: Pagination\n    ) {\n        vulnerabilityRequests(\n            query: $query\n            requestIDSelector: $requestIDSelector\n            pagination: $pagination\n        ) {\n            id\n            targetState\n            status\n            requestor {\n                id\n                name\n            }\n            comments {\n                createdAt\n                id\n                message\n                user {\n                    id\n                    name\n                }\n            }\n            scope {\n                imageScope {\n                    registry\n                    remote\n                    tag\n                }\n            }\n            deferralReq {\n                expiresOn\n                expiresWhenFixed\n            }\n            updatedDeferralReq {\n                expiresOn\n                expiresWhenFixed\n            }\n            cves {\n                cves\n            }\n            deployments(query: $query) {\n                id\n                name\n                namespace\n                clusterName\n            }\n            deploymentCount(query: $query)\n            images(query: $query) {\n                id\n                name {\n                    fullName\n                }\n            }\n            imageCount(query: $query)\n        }\n        vulnerabilityRequestsCount(query: $query)\n    }\n'
): (typeof documents)['\n    query getVulnerabilityRequests(\n        $query: String\n        $requestIDSelector: String\n        $pagination: Pagination\n    ) {\n        vulnerabilityRequests(\n            query: $query\n            requestIDSelector: $requestIDSelector\n            pagination: $pagination\n        ) {\n            id\n            targetState\n            status\n            requestor {\n                id\n                name\n            }\n            comments {\n                createdAt\n                id\n                message\n                user {\n                    id\n                    name\n                }\n            }\n            scope {\n                imageScope {\n                    registry\n                    remote\n                    tag\n                }\n            }\n            deferralReq {\n                expiresOn\n                expiresWhenFixed\n            }\n            updatedDeferralReq {\n                expiresOn\n                expiresWhenFixed\n            }\n            cves {\n                cves\n            }\n            deployments(query: $query) {\n                id\n                name\n                namespace\n                clusterName\n            }\n            deploymentCount(query: $query)\n            images(query: $query) {\n                id\n                name {\n                    fullName\n                }\n            }\n            imageCount(query: $query)\n        }\n        vulnerabilityRequestsCount(query: $query)\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    mutation approveVulnerabilityRequest($requestID: ID!, $comment: String!) {\n        approveVulnerabilityRequest(requestID: $requestID, comment: $comment) {\n            id\n        }\n    }\n'
): (typeof documents)['\n    mutation approveVulnerabilityRequest($requestID: ID!, $comment: String!) {\n        approveVulnerabilityRequest(requestID: $requestID, comment: $comment) {\n            id\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    mutation denyVulnerabilityRequest($requestID: ID!, $comment: String!) {\n        denyVulnerabilityRequest(requestID: $requestID, comment: $comment) {\n            id\n        }\n    }\n'
): (typeof documents)['\n    mutation denyVulnerabilityRequest($requestID: ID!, $comment: String!) {\n        denyVulnerabilityRequest(requestID: $requestID, comment: $comment) {\n            id\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    mutation deleteVulnerabilityRequest($requestID: ID!) {\n        deleteVulnerabilityRequest(requestID: $requestID)\n    }\n'
): (typeof documents)['\n    mutation deleteVulnerabilityRequest($requestID: ID!) {\n        deleteVulnerabilityRequest(requestID: $requestID)\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    mutation undoVulnerabilityRequest($requestID: ID!) {\n        undoVulnerabilityRequest(requestID: $requestID) {\n            id\n        }\n    }\n'
): (typeof documents)['\n    mutation undoVulnerabilityRequest($requestID: ID!) {\n        undoVulnerabilityRequest(requestID: $requestID) {\n            id\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    mutation updateVulnerabilityRequest(\n        $requestID: ID!\n        $comment: String!\n        $expiry: VulnReqExpiry!\n    ) {\n        updateVulnerabilityRequest(requestID: $requestID, comment: $comment, expiry: $expiry) {\n            id\n        }\n    }\n'
): (typeof documents)['\n    mutation updateVulnerabilityRequest(\n        $requestID: ID!\n        $comment: String!\n        $expiry: VulnReqExpiry!\n    ) {\n        updateVulnerabilityRequest(requestID: $requestID, comment: $comment, expiry: $expiry) {\n            id\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    query getImageDetails($id: ID!) {\n        image(id: $id) {\n            id\n            name {\n                registry\n                remote\n                tag\n            }\n            ...ImageDetails\n        }\n    }\n'
): (typeof documents)['\n    query getImageDetails($id: ID!) {\n        image(id: $id) {\n            id\n            name {\n                registry\n                remote\n                tag\n            }\n            ...ImageDetails\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    \n    \n    \n    query getImageCoreVulnerabilities($id: ID!, $query: String!, $pagination: Pagination!) {\n        image(id: $id) {\n            ...ImageMetadataContext\n            imageCVECountBySeverity(query: $query) {\n                ...AllResourceCountsByCVESeverity\n            }\n            imageVulnerabilities(query: $query, pagination: $pagination) {\n                ...ImageVulnerabilityFields\n            }\n        }\n    }\n'
): (typeof documents)['\n    \n    \n    \n    query getImageCoreVulnerabilities($id: ID!, $query: String!, $pagination: Pagination!) {\n        image(id: $id) {\n            ...ImageMetadataContext\n            imageCVECountBySeverity(query: $query) {\n                ...AllResourceCountsByCVESeverity\n            }\n            imageVulnerabilities(query: $query, pagination: $pagination) {\n                ...ImageVulnerabilityFields\n            }\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    \n    query getImageCveMetadata($cve: String!) {\n        imageCVE(cve: $cve) {\n            ...ImageCVEMetadata\n        }\n    }\n'
): (typeof documents)['\n    \n    query getImageCveMetadata($cve: String!) {\n        imageCVE(cve: $cve) {\n            ...ImageCVEMetadata\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    \n    \n    query getImageCveSummaryData($cve: String!, $query: String!) {\n        ...ImageCVESummaryCounts\n        imageCount(query: $query)\n        deploymentCount(query: $query)\n        imageCVE(cve: $cve, subfieldScopeQuery: $query) {\n            cve\n            ...ImageCVESeveritySummary\n        }\n    }\n'
): (typeof documents)['\n    \n    \n    query getImageCveSummaryData($cve: String!, $query: String!) {\n        ...ImageCVESummaryCounts\n        imageCount(query: $query)\n        deploymentCount(query: $query)\n        imageCVE(cve: $cve, subfieldScopeQuery: $query) {\n            cve\n            ...ImageCVESeveritySummary\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    \n    # by default, query must include the CVE id\n    query getImagesForCVE($query: String, $pagination: Pagination) {\n        images(query: $query, pagination: $pagination) {\n            ...ImagesForCVE\n        }\n    }\n'
): (typeof documents)['\n    \n    # by default, query must include the CVE id\n    query getImagesForCVE($query: String, $pagination: Pagination) {\n        images(query: $query, pagination: $pagination) {\n            ...ImagesForCVE\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    \n    # by default, query must include the CVE id\n    query getDeploymentsForCVE($query: String, $pagination: Pagination) {\n        deployments(query: $query, pagination: $pagination) {\n            ...DeploymentsForCVE\n        }\n    }\n'
): (typeof documents)['\n    \n    # by default, query must include the CVE id\n    query getDeploymentsForCVE($query: String, $pagination: Pagination) {\n        deployments(query: $query, pagination: $pagination) {\n            ...DeploymentsForCVE\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    fragment ImageCVEMetadata on ImageCVECore {\n        cve\n        # TODO summary\n        # TODO url\n        firstDiscoveredInSystem\n    }\n'
): (typeof documents)['\n    fragment ImageCVEMetadata on ImageCVECore {\n        cve\n        # TODO summary\n        # TODO url\n        firstDiscoveredInSystem\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    fragment ImageCVESeveritySummary on ImageCVECore {\n        affectedImageCountBySeverity {\n            critical {\n                total\n            }\n            important {\n                total\n            }\n            moderate {\n                total\n            }\n            low {\n                total\n            }\n        }\n        affectedImageCount\n        topCVSS\n        # TODO vector\n    }\n'
): (typeof documents)['\n    fragment ImageCVESeveritySummary on ImageCVECore {\n        affectedImageCountBySeverity {\n            critical {\n                total\n            }\n            important {\n                total\n            }\n            moderate {\n                total\n            }\n            low {\n                total\n            }\n        }\n        affectedImageCount\n        topCVSS\n        # TODO vector\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    fragment ImageCVESummaryCounts on Query {\n        totalImageCount: imageCount\n    }\n'
): (typeof documents)['\n    fragment ImageCVESummaryCounts on Query {\n        totalImageCount: imageCount\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    query getEntityTypeCounts($query: String) {\n        imageCount(query: $query)\n        deploymentCount(query: $query)\n        imageCVECount(query: $query)\n    }\n'
): (typeof documents)['\n    query getEntityTypeCounts($query: String) {\n        imageCount(query: $query)\n        deploymentCount(query: $query)\n        imageCVECount(query: $query)\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    fragment AllResourceCountsByCVESeverity on ResourceCountByCVESeverity {\n        low {\n            total\n            fixable\n        }\n        moderate {\n            total\n            fixable\n        }\n        important {\n            total\n            fixable\n        }\n        critical {\n            total\n            fixable\n        }\n    }\n'
): (typeof documents)['\n    fragment AllResourceCountsByCVESeverity on ResourceCountByCVESeverity {\n        low {\n            total\n            fixable\n        }\n        moderate {\n            total\n            fixable\n        }\n        important {\n            total\n            fixable\n        }\n        critical {\n            total\n            fixable\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    \n    \n    fragment DeploymentsForCVE on Deployment {\n        id\n        name\n        namespace\n        clusterName\n        created\n        imageCount(query: $query)\n        images(query: $query) {\n            ...ImageMetadataContext\n            imageComponents(query: $query) {\n                ...ComponentVulnerabilities\n            }\n        }\n    }\n'
): (typeof documents)['\n    \n    \n    fragment DeploymentsForCVE on Deployment {\n        id\n        name\n        namespace\n        clusterName\n        created\n        imageCount(query: $query)\n        images(query: $query) {\n            ...ImageMetadataContext\n            imageComponents(query: $query) {\n                ...ComponentVulnerabilities\n            }\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    \n    \n    fragment ImagesForCVE on Image {\n        ...ImageMetadataContext\n\n        operatingSystem\n        watchStatus\n        scanTime\n\n        imageComponents(query: $query) {\n            ...ComponentVulnerabilities\n        }\n    }\n'
): (typeof documents)['\n    \n    \n    fragment ImagesForCVE on Image {\n        ...ImageMetadataContext\n\n        operatingSystem\n        watchStatus\n        scanTime\n\n        imageComponents(query: $query) {\n            ...ComponentVulnerabilities\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    query getImageCVEList($query: String, $pagination: Pagination) {\n        imageCVEs(query: $query, pagination: $pagination) {\n            cve\n            affectedImageCountBySeverity {\n                critical {\n                    total\n                }\n                important {\n                    total\n                }\n                moderate {\n                    total\n                }\n                low {\n                    total\n                }\n            }\n            topCVSS\n            affectedImageCount\n            firstDiscoveredInSystem\n        }\n    }\n'
): (typeof documents)['\n    query getImageCVEList($query: String, $pagination: Pagination) {\n        imageCVEs(query: $query, pagination: $pagination) {\n            cve\n            affectedImageCountBySeverity {\n                critical {\n                    total\n                }\n                important {\n                    total\n                }\n                moderate {\n                    total\n                }\n                low {\n                    total\n                }\n            }\n            topCVSS\n            affectedImageCount\n            firstDiscoveredInSystem\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    query getUnfilteredImageCount {\n        imageCount\n    }\n'
): (typeof documents)['\n    query getUnfilteredImageCount {\n        imageCount\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    fragment ImageMetadataContext on Image {\n        id\n        name {\n            registry\n            remote\n            tag\n        }\n        metadata {\n            v1 {\n                layers {\n                    instruction\n                    value\n                }\n            }\n        }\n    }\n'
): (typeof documents)['\n    fragment ImageMetadataContext on Image {\n        id\n        name {\n            registry\n            remote\n            tag\n        }\n        metadata {\n            v1 {\n                layers {\n                    instruction\n                    value\n                }\n            }\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    fragment ComponentVulnerabilities on ImageComponent {\n        name\n        version\n        location\n        layerIndex\n        imageVulnerabilities(query: $query) {\n            id\n            severity\n            fixedByVersion\n        }\n    }\n'
): (typeof documents)['\n    fragment ComponentVulnerabilities on ImageComponent {\n        name\n        version\n        location\n        layerIndex\n        imageVulnerabilities(query: $query) {\n            id\n            severity\n            fixedByVersion\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    query getDeploymentList($query: String, $pagination: Pagination) {\n        deployments(query: $query, pagination: $pagination) {\n            id\n            name\n            imageCVECountBySeverity(query: $query) {\n                critical {\n                    total\n                }\n                important {\n                    total\n                }\n                moderate {\n                    total\n                }\n                low {\n                    total\n                }\n            }\n            clusterName\n            namespace\n            imageCount(query: $query)\n            created\n        }\n    }\n'
): (typeof documents)['\n    query getDeploymentList($query: String, $pagination: Pagination) {\n        deployments(query: $query, pagination: $pagination) {\n            id\n            name\n            imageCVECountBySeverity(query: $query) {\n                critical {\n                    total\n                }\n                important {\n                    total\n                }\n                moderate {\n                    total\n                }\n                low {\n                    total\n                }\n            }\n            clusterName\n            namespace\n            imageCount(query: $query)\n            created\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    query getImageList($query: String, $pagination: Pagination) {\n        images(query: $query, pagination: $pagination) {\n            id\n            name {\n                registry\n                remote\n                tag\n            }\n            imageCVECountBySeverity(query: $query) {\n                critical {\n                    total\n                }\n                important {\n                    total\n                }\n                moderate {\n                    total\n                }\n                low {\n                    total\n                }\n            }\n            operatingSystem\n            deploymentCount(query: $query)\n            watchStatus\n            metadata {\n                v1 {\n                    created\n                }\n            }\n            scanTime\n        }\n    }\n'
): (typeof documents)['\n    query getImageList($query: String, $pagination: Pagination) {\n        images(query: $query, pagination: $pagination) {\n            id\n            name {\n                registry\n                remote\n                tag\n            }\n            imageCVECountBySeverity(query: $query) {\n                critical {\n                    total\n                }\n                important {\n                    total\n                }\n                moderate {\n                    total\n                }\n                low {\n                    total\n                }\n            }\n            operatingSystem\n            deploymentCount(query: $query)\n            watchStatus\n            metadata {\n                v1 {\n                    created\n                }\n            }\n            scanTime\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    \n    fragment ImageVulnerabilityFields on ImageVulnerability {\n        id\n        severity\n        isFixable\n        cve\n        summary\n        cvss\n        scoreVersion\n        discoveredAtImage\n        imageComponents(query: $query) {\n            ...ComponentVulnerabilities\n        }\n    }\n'
): (typeof documents)['\n    \n    fragment ImageVulnerabilityFields on ImageVulnerability {\n        id\n        severity\n        isFixable\n        cve\n        summary\n        cvss\n        scoreVersion\n        discoveredAtImage\n        imageComponents(query: $query) {\n            ...ComponentVulnerabilities\n        }\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    fragment ImageDetails on Image {\n        id\n        deploymentCount\n        operatingSystem\n        metadata {\n            v1 {\n                created\n                digest\n            }\n        }\n        dataSource {\n            id\n            name\n        }\n        scanTime\n    }\n'
): (typeof documents)['\n    fragment ImageDetails on Image {\n        id\n        deploymentCount\n        operatingSystem\n        metadata {\n            v1 {\n                created\n                digest\n            }\n        }\n        dataSource {\n            id\n            name\n        }\n        scanTime\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    query deployments($query: String) {\n        count: deploymentCount(query: $query)\n    }\n'
): (typeof documents)['\n    query deployments($query: String) {\n        count: deploymentCount(query: $query)\n    }\n'];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
    source: '\n    query getNamespaceDeployments($query: String!) {\n        results: namespaces(query: $query) {\n            metadata {\n                name\n                id\n            }\n            deployments {\n                name\n                id\n            }\n        }\n    }\n'
): (typeof documents)['\n    query getNamespaceDeployments($query: String!) {\n        results: namespaces(query: $query) {\n            metadata {\n                name\n                id\n            }\n            deployments {\n                name\n                id\n            }\n        }\n    }\n'];

export function graphql(source: string) {
    return (documents as any)[source] ?? {};
}

export type DocumentType<TDocumentNode extends DocumentNode<any, any>> =
    TDocumentNode extends DocumentNode<infer TType, any> ? TType : never;
