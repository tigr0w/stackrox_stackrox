import type { Snapshot } from 'types/reportJob';
import type { VulnerabilitySeverity } from '../types/cve.proto';

// Report configuration types

export type ReportConfiguration = {
    id: string;
    name: string;
    description: string;
    type: ReportType;
    vulnReportFilters: VulnerabilityReportFilters;
    notifiers: NotifierConfiguration[];
    schedule: Schedule | null;
    resourceScope: ResourceScope;
};

export type ReportType = 'VULNERABILITY';

export type VulnerabilityReportFiltersBase = {
    fixability: Fixability;
    severities: VulnerabilitySeverity[];
    imageTypes: ImageType[];
    includeAdvisory: boolean;
    includeEpssProbability: boolean;
    includeNvdCvss: boolean;
};

export type VulnerabilityReportFilters =
    | (VulnerabilityReportFiltersBase & {
          allVuln: boolean;
      })
    | (VulnerabilityReportFiltersBase & {
          sinceLastSentScheduledReport: boolean;
      })
    | (VulnerabilityReportFiltersBase & {
          sinceStartDate: string; // in the format of google.protobuf.Timestamp};
      });

export type OnDemandVulnerabilityReportFilters = {
    imageTypes: ImageType[];
    includeEpssProbability: boolean;
    includeNvdCvss: boolean;
    query: string;
};

export type Fixability = 'BOTH' | 'FIXABLE' | 'NOT_FIXABLE';

export const imageTypes = ['DEPLOYED', 'WATCHED'] as const;

export type ImageType = (typeof imageTypes)[number];

export type NotifierConfiguration = {
    emailConfig: {
        notifierId: string;
        mailingLists: string[];
        customSubject: string;
        customBody: string;
    };
    notifierName: string;
};

export type Schedule =
    | {
          intervalType: 'WEEKLY';
          hour: number;
          minute: number;
          daysOfWeek: DaysOfWeek;
      }
    | {
          intervalType: 'MONTHLY';
          hour: number;
          minute: number;
          daysOfMonth: DaysOfMonth;
      };

export const intervalTypes = ['WEEKLY', 'MONTHLY'] as const;

export type IntervalType = (typeof intervalTypes)[number];

export type Interval = DaysOfWeek | DaysOfMonth;

// Sunday = 0, Monday = 1, .... Saturday =  6
export type DaysOfWeek = {
    days: number[]; // int32
};

// 1 for 1st, 2 for 2nd .... 31 for 31st
export type DaysOfMonth = {
    days: number[]; // int32
};

export type ResourceScope = {
    collectionScope: {
        collectionId: string;
        collectionName: string;
    };
};

// Report history

export type ReportHistoryResponse = {
    reportSnapshots: ReportSnapshot[];
};

export type ReportSnapshot = Snapshot & {
    reportConfigId: string;
    vulnReportFilters: VulnerabilityReportFilters;
    collectionSnapshot: CollectionSnapshot;
    schedule: Schedule | null;
    notifiers: NotifierConfiguration[];
};

// @TODO: Technically, this type will have the same fields as ReportSnapshot but the irrelevant
// ones will be null or empty. For now, I didn't include them
export type OnDemandReportSnapshot = Snapshot & {
    requestName: string;
    isOnDemand: boolean;
    areaOfConcern: string;
    vulnReportFilters: OnDemandVulnerabilityReportFilters;
};

export type CollectionSnapshot = {
    id: string;
    name: string;
};

// Misc types

export type RunReportResponse = {
    reportConfigId: string;
    reportId: string;
};
