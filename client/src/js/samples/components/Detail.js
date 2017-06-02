/**
 *
 *
 * @copyright 2017 Government of Canada
 * @license MIT
 * @author igboyes
 *
 */

import React from "react";
import { Route, Redirect } from "react-router-dom";
import { connect } from "react-redux";
import { LinkContainer } from "react-router-bootstrap";
import { Nav, NavItem, Modal } from "react-bootstrap";

import { getSample } from "../actions";
import { Spinner } from "virtool/js/components/Base";
import General from "./Detail/General";

class SampleDetail extends React.Component {

    modalEnter = () => {
        this.props.getSample(this.props.match.params.sampleId);
    };

    hide = () => {
        this.props.history.push("/samples");
    };

    render () {

        const sampleId = this.props.match.params.sampleId;

        let header;
        let content;

        if (this.props.detail === null) {
            content = (
                <div className="text-center">
                    <Spinner />
                </div>
            );
        } else {
            header = (
                <Modal.Header onHide={this.hide}>
                    {this.props.detail.name}
                </Modal.Header>
            );

            content = (
                <div>
                    <Redirect from="/samples/detail/:sampleId" to={`/samples/detail/${sampleId}/general`} exact />

                    <Nav bsStyle="tabs">
                        <LinkContainer to={`/samples/detail/${sampleId}/general`}>
                            <NavItem>General</NavItem>
                        </LinkContainer>
                        <LinkContainer to={`/samples/detail/${sampleId}/quality`}>
                            <NavItem>Quality</NavItem>
                        </LinkContainer>
                        <LinkContainer to={`/samples/detail/${sampleId}/analyses`}>
                            <NavItem>Analyses</NavItem>
                        </LinkContainer>
                    </Nav>

                    <Route path="/samples/detail/:sampleId/general" component={General} />
                </div>
            );
        }

        return (
            <Modal bsSize="lg" show={true} onHide={this.hide} onEnter={this.modalEnter}>
                {header}
                <Modal.Body>
                    {content}
                </Modal.Body>
            </Modal>
        );
    }
}

const mapStateToProps = (state) => {
    return {
        detail: state.samples.detail
    };
};

const mapDispatchToProps = (dispatch) => {
    return {
        getSample: (sampleId) => {
            dispatch(getSample(sampleId));
        }
    };
};

const Container = connect(mapStateToProps, mapDispatchToProps)(SampleDetail);

export default Container;

