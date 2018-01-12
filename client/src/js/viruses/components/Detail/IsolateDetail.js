import React from "react";
import { capitalize } from "lodash";
import { connect } from "react-redux";
import { Label, Panel, Table } from "react-bootstrap";

import EditIsolate from "./EditIsolate";
import IsolateSequences from "./Sequences";
import RemoveIsolate from "./RemoveIsolate";
import { Icon, IDRow } from "../../../base";
import { followDownload } from "../../../utils";
import { setIsolateAsDefault, showEditIsolate, showRemoveIsolate } from "../../actions";

const IsolateTable = ({ id, isDefault, isolateName, sourceName, sourceType }) => (
    <Table bordered>
        <tbody>
            <tr>
                <th className="col-md-3">Name</th>
                <td className="col-md-9">{isolateName}</td>
            </tr>
            <tr>
                <th>Source Type</th>
                <td>{capitalize(sourceType)}</td>
            </tr>
            <tr>
                <th>Source Name</th>
                <td>{sourceName}</td>
            </tr>
            <tr>
                <th>Default</th>
                <td>
                    <Label bsStyle={isDefault ? "success" : "default"}>
                        {isDefault ? "Yes" : "No"}
                    </Label>
                </td>
            </tr>
            <IDRow id={id} />
        </tbody>
    </Table>
);

const IsolateDetail = (props) => {

    const isolate = props.activeIsolate;

    const defaultIsolateLabel = (
        <Label bsStyle="info" style={{visibility: props.default ? "visible" : "hidden"}}>
            <Icon name="star" /> Default Isolate
        </Label>
    );

    let modifyIcons;

    if (props.canModify) {
        modifyIcons = (
            <span>
                <Icon
                    name="pencil"
                    bsStyle="warning"
                    tip="Edit Name"
                    onClick={props.showEditIsolate}
                    style={{paddingLeft: "7px"}}
                />

                {isolate.default ? null : (
                    <Icon
                        name="star"
                        bsStyle="success"
                        tip="Set as Default"
                        onClick={() => props.setIsolateAsDefault(props.virusId, isolate.id)}
                        style={{paddingLeft: "3px"}}
                    />
                )}

                <Icon
                    name="remove"
                    bsStyle="danger"
                    tip="Remove Isolate"
                    onClick={props.showRemoveIsolate}
                    style={{paddingLeft: "3px"}}
                />
            </span>
        );
    }

    return (
        <div>
            <EditIsolate
                virusId={props.virusId}
                isolateId={isolate.id}
                sourceType={isolate.source_type}
                sourceName={isolate.source_name}
            />

            <RemoveIsolate
                virusId={props.virusId}
                isolateId={isolate.id}
                isolateName={isolate.name}
                nextIsolateId={props.isolates.length ? props.isolates[0].id : null}
            />

            <Panel>
                <h5 style={{display: "flex", alignItems: "center", marginBottom: "15px"}}>
                    <strong style={{flex: "1 0 auto"}}>{isolate.name}</strong>

                    {defaultIsolateLabel}
                    {modifyIcons}

                    <Icon
                        name="download"
                        tip="Download FASTA"
                        style={{paddingLeft: "3px"}}
                        onClick={() => followDownload(
                            `/download/viruses/${props.virusId}/isolates/${isolate.id}`
                        )}
                    />
                </h5>

                <IsolateTable
                    id={isolate.id}
                    isDefault={isolate.default}
                    isolateName={isolate.name}
                    sourceName={isolate.sourceName}
                    sourceType={isolate.sourceType}
                />

                <IsolateSequences />
            </Panel>
        </div>
    );
};

const mapStateToProps = state => ({
    isolates: state.viruses.detail.isolates,
    virusId: state.viruses.detail.id,
    activeIsolate: state.viruses.activeIsolate,
    activeIsolateId: state.viruses.activeIsolateId,
    activeSequenceId: state.viruses.activeSequenceId,
    editing: state.viruses.editingIsolate,
    allowedSourceTypes: state.settings.data.allowed_source_types,
    restrictSourceTypes: state.settings.data.restrict_source_types,
    canModify: state.account.permissions.modify_virus
});

const mapDispatchToProps = (dispatch) => ({

    setIsolateAsDefault: (virusId, isolateId) => {
        dispatch(setIsolateAsDefault(virusId, isolateId));
    },

    showEditIsolate: (virusId, isolateId, sourceType, sourceName) => {
        dispatch(showEditIsolate(virusId, isolateId, sourceType, sourceName));
    },

    showRemoveIsolate: () => {
        dispatch(showRemoveIsolate());
    }

});

const Container = connect(mapStateToProps, mapDispatchToProps)(IsolateDetail);

export default Container;
