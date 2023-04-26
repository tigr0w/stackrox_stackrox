import React, { ReactNode } from 'react';
import {
    Breadcrumb,
    BreadcrumbItem,
    Bullseye,
    Divider,
    Flex,
    PageSection,
    Skeleton,
    Tab,
    Tabs,
    TabsComponent,
    TabTitleText,
    Title,
} from '@patternfly/react-core';
import { ExclamationCircleIcon } from '@patternfly/react-icons';
import { useParams } from 'react-router-dom';
import { useQuery } from '@apollo/client';

import { graphql } from 'gql';
import BreadcrumbItemLink from 'Components/BreadcrumbItemLink';
import PageTitle from 'Components/PageTitle';
import useURLStringUnion from 'hooks/useURLStringUnion';
import EmptyStateTemplate from 'Components/PatternFly/EmptyStateTemplate';
import { getAxiosErrorMessage } from 'utils/responseErrorUtils';
import ImageDetailBadges from '../components/ImageDetailBadges';
import { getOverviewCvesPath } from '../searchUtils';
import { detailsTabValues } from '../types';
import ImagePageResources from './ImagePageResources';
import ImagePageVulnerabilities from './ImagePageVulnerabilities';

const workloadCveOverviewImagePath = getOverviewCvesPath({
    cveStatusTab: 'Observed',
    entityTab: 'Image',
});

export const imageDetailsQuery = graphql(/* GraphQL */ `
    query getImageDetails($id: ID!) {
        image(id: $id) {
            id
            name {
                registry
                remote
                tag
            }
            ...ImageDetails
        }
    }
`);

function ImagePage() {
    const { imageId } = useParams();
    const { data, error } = useQuery(imageDetailsQuery, {
        variables: { id: imageId },
    });
    const [activeTabKey, setActiveTabKey] = useURLStringUnion('detailsTab', detailsTabValues);

    const imageData = data && data.image;
    const imageName = imageData?.name
        ? `${imageData.name.registry}/${imageData.name.remote}:${imageData.name.tag}`
        : 'NAME UNKNOWN';

    let mainContent: ReactNode | null = null;

    if (error) {
        mainContent = (
            <PageSection variant="light">
                <Bullseye>
                    <EmptyStateTemplate
                        title={getAxiosErrorMessage(error)}
                        headingLevel="h2"
                        icon={ExclamationCircleIcon}
                        iconClassName="pf-u-danger-color-100"
                    />
                </Bullseye>
            </PageSection>
        );
    } else {
        mainContent = (
            <>
                <PageSection variant="light">
                    {imageData ? (
                        <Flex direction={{ default: 'column' }}>
                            <Title headingLevel="h1" className="pf-u-mb-sm">
                                {imageName}
                            </Title>
                            <ImageDetailBadges imageData={imageData} />
                        </Flex>
                    ) : (
                        <Flex
                            direction={{ default: 'column' }}
                            spaceItems={{ default: 'spaceItemsXs' }}
                            className="pf-u-w-50"
                        >
                            <Skeleton screenreaderText="Loading image name" fontSize="2xl" />
                            <Skeleton screenreaderText="Loading image metadata" fontSize="sm" />
                        </Flex>
                    )}
                </PageSection>
                <PageSection
                    className="pf-u-display-flex pf-u-flex-direction-column pf-u-flex-grow-1"
                    padding={{ default: 'noPadding' }}
                >
                    <Tabs
                        activeKey={activeTabKey}
                        onSelect={(e, key) => setActiveTabKey(key)}
                        component={TabsComponent.nav}
                        className="pf-u-pl-md pf-u-background-color-100"
                        mountOnEnter
                        unmountOnExit
                    >
                        <Tab
                            className="pf-u-display-flex pf-u-flex-direction-column pf-u-flex-grow-1"
                            eventKey="Vulnerabilities"
                            title={<TabTitleText>Vulnerabilities</TabTitleText>}
                        >
                            <ImagePageVulnerabilities imageId={imageId} />
                        </Tab>
                        <Tab
                            className="pf-u-display-flex pf-u-flex-direction-column pf-u-flex-grow-1"
                            eventKey="Resources"
                            title={<TabTitleText>Resources</TabTitleText>}
                            isDisabled
                        >
                            <ImagePageResources />
                        </Tab>
                    </Tabs>
                </PageSection>
            </>
        );
    }

    return (
        <>
            <PageTitle title={`Workload CVEs - Image ${imageData ? imageName : ''}`} />
            <PageSection variant="light" className="pf-u-py-md">
                <Breadcrumb>
                    <BreadcrumbItemLink to={workloadCveOverviewImagePath}>
                        Images
                    </BreadcrumbItemLink>
                    {!error && (
                        <BreadcrumbItem isActive>
                            {imageData ? (
                                imageName
                            ) : (
                                <Skeleton screenreaderText="Loading image name" width="200px" />
                            )}
                        </BreadcrumbItem>
                    )}
                </Breadcrumb>
            </PageSection>
            <Divider component="div" />
            {mainContent}
        </>
    );
}

export default ImagePage;
