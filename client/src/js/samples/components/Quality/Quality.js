/**
 * @license
 * The MIT License (MIT)
 * Copyright 2015 Government of Canada
 *
 * @author
 * Ian Boyes
 *
 * @exports Quality
 */

import React from "react";
import { pick } from "lodash";
import { connect } from "react-redux";

import { Button } from "../../../base";
import Chart from "./Chart";
import Bases from "./Bases";
import Nucleotides from "./Nucleotides";
import Sequences from "./Sequences";

const SampleDetailQuality = (props) => (
    <div className="printable-quality">
        <h5>
            <strong>Quality Distribution at Read Positions</strong>
            <Button type="button" bsStyle="info" bsSize="xsmall" icon="print" onClick={() => window.print()} pullRight>
                Print
            </Button>
        </h5>
        <Chart
            createChart={Bases}
            data={props.bases}
        />

        <h5><strong>Nucleotide Composition at Read Positions</strong></h5>
        <Chart
            createChart={Nucleotides}
            data={props.composition}
        />

        <h5><strong>Read-wise Quality Occurrence</strong></h5>
        <Chart
            createChart={Sequences}
            data={props.sequences}
        />
    </div>
);

const mapStateToProps = (state) => {
    return pick(state.samples.detail.quality, ["bases", "composition", "sequences"]);
};

const Container = connect(mapStateToProps)(SampleDetailQuality);

export default Container;