/**
 *
 *
 * @copyright 2017 Government of Canada
 * @license MIT
 * @author igboyes
 *
 */

import React from "react";
import { connect } from "react-redux";
import { Switch, Route } from "react-router-dom";

import { findViruses } from "../actions";
import VirusesList from "./Manage/List";
import VirusDetail from "./Manage/Detail";

const Viruses = () => {
    return (
        <div className="container">
            <Switch>
                <Route path="/viruses" component={VirusesList} exact />
                <Route path="/viruses/create" component={VirusesList} />
                <Route path="/viruses/:virusId" component={VirusDetail} />
            </Switch>
        </div>
    );
};

const mapStateToProps = (state) => {
    return {
        documents: state.viruses.documents,
        finding: state.viruses.finding,
        find: state.viruses.find,
        sort: state.viruses.sort,
        descending: state.viruses.descending,
        modified: state.viruses.modified,
        account: state.account
    };
};

const mapDispatchToProps = (dispatch, ownProps) => {
    return {
        onFind: (term) => {
            dispatch(findViruses({find: term || null}));
        },

        onToggleModifiedOnly: () => {
            dispatch(findViruses({modified: !ownProps.modified}));
        }
    };
};

const Container = connect(
    mapStateToProps,
    mapDispatchToProps
)(Viruses);

export default Container;
