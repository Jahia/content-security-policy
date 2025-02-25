<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<%@ page language="java" contentType="text/html;charset=UTF-8" %>
<%@ taglib prefix="template" uri="http://www.jahia.org/tags/templateLib" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<%@ taglib prefix="jcr" uri="http://www.jahia.org/tags/jcr" %>

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />

    <title>${fn:escapeXml(renderContext.mainResource.node.displayableName)}</title>
</head>

<body>

<div class="body">
    This is a sample view
</div>

<c:if test="${renderContext.editMode}">
    <template:addResources type="css" resources="edit.css" />
</c:if>
<template:addResources type="css" resources="960.css,01web.css"/>
<template:theme/>

</body>
</html>
