import React from 'react';
import { Select, SelectOption } from '@patternfly/react-core';

import useSelectToggle from 'hooks/patternfly/useSelectToggle';

export type EdgeState = 'active' | 'inactive' | 'inactive with dns';

type EdgeStateSelectProps = {
    edgeState: EdgeState;
    setEdgeState: (state) => void;
    isDisabled: boolean;
};

function EdgeStateSelect({ edgeState, setEdgeState, isDisabled }: EdgeStateSelectProps) {
    const { isOpen, onToggle, closeSelect } = useSelectToggle();

    function onSelect(_event, selection) {
        closeSelect();
        setEdgeState(selection);
    }

    return (
        <Select
            variant="single"
            isOpen={isOpen}
            onToggle={onToggle}
            onSelect={onSelect}
            selections={edgeState}
            isDisabled={isDisabled}
            id="edge-state-select"
        >
            <SelectOption
                value="active"
                description="Traffic observed in your selected time window."
            >
                Active traffic
            </SelectOption>
            <SelectOption
                value="inactive"
                description="Inactive flows allowed by your network policies in your selected time window."
            >
                Inactive flows
            </SelectOption>
            <SelectOption value="inactive with dns">Inactive flows with DNS flows</SelectOption>
        </Select>
    );
}

export default EdgeStateSelect;
