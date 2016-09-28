<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Inherits="SAML_Teste.WebForm1" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
</head>
<body>
    <form id="form1" runat="server" action="https://localhost:9031/sp/ACS.saml2">     
        <input type="text" style="width: 400px" name="RelayState" 
            value="http://localhost/SpSample/?foo=bar" /> 
        <input type="hidden" name="SAMLResponse" id="SAMLResponse" runat="server" />
        <input type="submit"/>                
    </form>
</body>
</html>
