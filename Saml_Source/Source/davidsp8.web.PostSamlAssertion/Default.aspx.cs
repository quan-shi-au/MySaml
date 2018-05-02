using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace davidsp8.web.PostSamlAssertion {
    public partial class _Default : System.Web.UI.Page {
        protected void Page_Load(object sender, EventArgs e) {

        }

        protected void btnLogin_Click(object sender, EventArgs e) {
            this.Session.Add("Email", txtEmail.Text);
            txtEmail.Enabled = false;
            lnkSSO.Visible = true;
            btnLogin.Visible = false;
        }
    }
}
