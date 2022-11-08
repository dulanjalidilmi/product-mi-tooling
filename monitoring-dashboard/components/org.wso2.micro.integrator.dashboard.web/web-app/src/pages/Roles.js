/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 *
 */

import React from 'react';
import EnhancedTable from '../commons/EnhancedTable';
import { useSelector } from 'react-redux';
import AuthManager from "../auth/AuthManager";
import {Link, Redirect} from "react-router-dom";
import {Button} from "@material-ui/core";
import {makeStyles} from "@material-ui/core/styles";
import Alert from '@material-ui/lab/Alert';

export default function Roles() {
    const [pageInfo] = React.useState({
        pageId: "roles",
        title: "Roles",
        headCells: [
            {id: 'roleName', label: 'Role Name'},
            {id: 'roleAction', label: 'Action'}],
        tableOrderBy: 'name'
    });

    const [error, setError] = React.useState(null);
    const classes = useStyles();
    const globalGroupId = useSelector(state => state.groupId);
    const dataSet = useSelector(state => state.data);

    React.useEffect(() => {
    
    }, [globalGroupId, dataSet]);

    if (AuthManager.getUser().scope !== "admin" || AuthManager.getUser().sso) {
        return (
            <Redirect to={{pathname: '/'}}/>
        );
    }

    if (error) {
        return (
        <div>
            <Alert severity="error">
                {error}
            </Alert>
        </div>
        );
    }

    return <>
        <div style={{height: "30px"}}>
        <Button classes={{root: classes.buttonRight}} component={Link} to="/roles/add" variant="contained"
                color="primary">
            Add New Role
        </Button>
        </div>
        <br/>
        <EnhancedTable pageInfo={pageInfo}/>
    </>
}

const useStyles = makeStyles((theme) => ({
    buttonRight: {
        float: "right"
    }
}));
