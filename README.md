<a href="https://www.jahia.com/">
    <img src="https://www.jahia.com/modules/jahiacom-templates/images/jahia-3x.png" alt="Jahia logo" title="Jahia" align="right" height="60" />
</a>

content-security-policy
=====================

The purpose of this module is to allow the definition of a Content Security Policy for a website inside [Digital Experience Manager](https://www.jahia.com).
For more information about the **Content Security Policy**, please refer to this URL: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy

# Installation

- In DX, go to "Administration --> Server settings --> System components --> Modules"
- Upload the JAR **content-security-policyt-X.X.X.jar**
- Check that the module is started

# Use

## Administration

- Go to "Administration -> Server settings -> Web Projects"
- Edit the site with which you want to use this module and add it to the list of the deployed modules

## Edit mode

 * CSP at the site level:
   * Go to the "Edit mode", right click on the root of the site and edit it
   * Go to the tab "Options" and activate the item "Add Content Security Policy at the site level"
   * Add in the text area the policy on one line
 * CSP at the page level:
   * Go to the "Edit mode", right click on the page and edit it
   * Go to the tab "Options" and activate the item "Add Content Security Policy at the page level"
   * Add in the text area the policy on one line
   * Publish the page

## Open-Source

This is an Open-Source module, you can find more details about Open-Source @ Jahia [in this repository](https://github.com/Jahia/open-source).
