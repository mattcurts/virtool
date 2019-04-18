import { connect } from "react-redux";
import { get, last } from "lodash-es";
import React from "react";
import styled from "styled-components";
import { Alert, ProgressBar } from "react-bootstrap";
import { Link } from "react-router-dom";
import { Box, BoxTitle, Flex } from "../../../base";
import { getHasRawFilesOnly } from "../../selectors";

const SampleFilesJobStatus = styled.span`
    color: #777777;
    font-size: 12px;
    text-transform: uppercase;
`;

export const SampleFilesJobMessage = ({ job }) => {
    const latest = last(job.status);
    return (
        <Box>
            <BoxTitle>
                <Flex alignItems="flex-end" justifyContent="space-between">
                    <Link to={`/jobs/${job.id}`}>Update job in progress</Link>
                    <SampleFilesJobStatus>{latest.state}</SampleFilesJobStatus>
                </Flex>
            </BoxTitle>
            <ProgressBar now={latest.progress * 100} />
        </Box>
    );
};

export const SampleFilesLegacyAlert = () => (
    <Alert bsStyle="warning">
        <p className="text-strong">
            Virtool now retains raw data for newly created samples instead of trimming during sample creation.
        </p>
        <p>
            Because this is an older sample, only trimmed data is available. You can upload the original sample files by
            dragging them onto the trimmed files they should replace.
        </p>
        <p>
            When replacements have been uploaded for all data files, an update job will start. No new analyses can be
            started for the sample during this time.
        </p>

        <p>
            <a target="_blank" rel="noopener noreferrer" href="https://www.virtool.ca/docs">
                More information
            </a>
        </p>
    </Alert>
);

export const SampleFilesMessage = ({ job, showJob, showLegacy }) => {
    if (showJob) {
        return <SampleFilesJobMessage job={job} />;
    }
    if (showLegacy) {
        return <SampleFilesLegacyAlert />;
    }

    return null;
};

const mapStateToProps = state => {
    const hasRawFilesOnly = getHasRawFilesOnly(state);
    const jobId = get(state, "samples.detail.update_job.id");

    const job = get(state, ["jobs", "linkedJobs", jobId]);

    return {
        job,
        showJob: !!job && !hasRawFilesOnly,
        showLegacy: !hasRawFilesOnly
    };
};

export default connect(mapStateToProps)(SampleFilesMessage);