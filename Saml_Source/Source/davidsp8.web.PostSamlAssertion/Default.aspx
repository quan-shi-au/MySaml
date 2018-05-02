<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Inherits="davidsp8.web.PostSamlAssertion._Default" EnableSessionState="True" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" >
<head runat="server">
    <title></title>
</head>
<body>
    <form id="form1" runat="server" defaultfocus="txtEmail" 
    defaultbutton="btnLogin">
    <div>
    
        <asp:Label ID="lblEmail" runat="server" Text="Email:"></asp:Label>&nbsp
        <asp:TextBox ID="txtEmail" runat="server"></asp:TextBox>&nbsp
        <asp:Button ID="btnLogin" runat="server" Text="Login" 
            onclick="btnLogin_Click" />&nbsp
    
        <asp:RegularExpressionValidator ID="RegularExpressionValidator1" runat="server" 
            ControlToValidate="txtEmail" ErrorMessage="Invalid Email" 
            
            ValidationExpression="^[\w\.\-]+@[a-zA-Z0-9\-]+(\.[a-zA-Z0-9\-]{1,})*(\.[a-zA-Z]{2,3}){1,2}$" 
            SetFocusOnError="True"></asp:RegularExpressionValidator>
    
        &nbsp<asp:HyperLink ID="lnkSSO" runat="server" NavigateUrl="SSO.aspx" 
            Target="_blank" Visible="False">SSO</asp:HyperLink>
    
    </div>
    </form>
</body>
</html>
