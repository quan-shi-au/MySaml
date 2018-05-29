using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Net;
using System.IO;
using System.Xml.Serialization;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using log4net;
using System.Xml.Schema;
using System.Xml;
using davidsp8.common.Security.Saml;

namespace davidsp8.windows.PostSamlAssertion {
    public partial class frmMain : Form {
        /// <summary>
        /// Configuration File Name
        /// </summary>
        private string configFileName = System.Environment.CurrentDirectory + @"\ConfigurationData.xml";
        /// <summary>
        /// Log4Net Logger
        /// </summary>
        private ILog Logger = LogManager.GetLogger(typeof(frmMain));
        /// <summary>
        /// Always Trust Certficate
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="certificate">Certificate</param>
        /// <param name="chain">X509 Chain</param>
        /// <param name="sslPolicyErrors">Policy Error</param>
        /// <returns></returns>
        private bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) {
            return true;
        }
        /// <summary>
        /// Form Constructor
        /// </summary>
        public frmMain() {
            InitializeComponent();
        }
        /// <summary>
        /// Update the Configuration File from Form values
        /// </summary>
        private void updateConfigurationFileFromForm() {
            configurationData.Configuration.Rows[0]["Recipient"] = this.txtRecipient.Text;
            configurationData.Configuration.Rows[0]["Subject"] = this.txtSubject.Text;
            configurationData.Configuration.Rows[0]["Target"] = this.txtTarget.Text;
            configurationData.Configuration.Rows[0]["Issuer"] = this.txtIssuer.Text;
            configurationData.Configuration.Rows[0]["Domain"] = this.txtDomain.Text;
            if (this.rb_v1.Checked) {
                configurationData.Configuration.Rows[0]["Version"] = "1.1";
            }
            if (this.rb_v2.Checked) {
                configurationData.Configuration.Rows[0]["Version"] = "2.0";
            }
        }
        /// <summary>
        /// Update the Form from ConfigurationFile values
        /// </summary>
        private void updateFormFromConfigurationFile() {
            this.txtRecipient.Text = configurationData.Configuration.Rows[0]["Recipient"].ToString();
            this.txtSubject.Text = configurationData.Configuration.Rows[0]["Subject"].ToString();
            this.txtTarget.Text = configurationData.Configuration.Rows[0]["Target"].ToString();
            this.txtIssuer.Text = configurationData.Configuration.Rows[0]["Issuer"].ToString();
            this.txtDomain.Text = configurationData.Configuration.Rows[0]["Domain"].ToString();
            this.lblCertificateFriendlyName.Text = configurationData.Configuration.Rows[0]["CertFriendlyName"].ToString();
            if (configurationData.Configuration.Rows[0]["Version"] != null) {
                if (configurationData.Configuration.Rows[0]["Version"].ToString() == "1.1") {
                    this.rb_v1.Checked = true;
                } else {
                    this.rb_v1.Checked = false;
                }
                if (configurationData.Configuration.Rows[0]["Version"].ToString() == "2.0") {
                    this.rb_v2.Checked = true;
                } else {
                    this.rb_v2.Checked = false;
                }
            }

        }
        /// <summary>
        /// Call the Saml Helper Class and get the "Post" value, which can then be posted to the web page
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnPostAssertion_Click(object sender, EventArgs e) {
            try {
                this.Cursor = Cursors.WaitCursor;

                // Set Attributes
                Dictionary<string, string> attributes = new Dictionary<string, string>();

                foreach (ConfigurationData.AttributesRow row in configurationData.Attributes.Rows) {
                    attributes.Add(row.Name, row.Value);
                }

                string postData = "";
                // Set Parameters to the method call to either the configuration value or a default value
                StoreLocation storeLocation = configurationData.Configuration.Rows[0]["CertStoreLocation"].ToString().Length> 0 ? (StoreLocation)Enum.Parse(typeof(StoreLocation),
                    configurationData.Configuration.Rows[0]["CertStoreLocation"].ToString()) : StoreLocation.LocalMachine;
                StoreName storeName = configurationData.Configuration.Rows[0]["CertStoreName"].ToString().Length> 0 ? (StoreName)Enum.Parse(typeof(StoreName),
                                configurationData.Configuration.Rows[0]["CertStoreName"].ToString()) : StoreName.Root;
                X509FindType findType = configurationData.Configuration.Rows[0]["CertFindMethod"].ToString().Length> 0 ? (X509FindType)Enum.Parse(typeof(X509FindType),
                                configurationData.Configuration.Rows[0]["CertFindMethod"].ToString()) : X509FindType.FindByThumbprint;
                string certFileLocation = configurationData.Configuration.Rows[0]["CertFileLocation"].ToString().Length> 0 ?
                                configurationData.Configuration.Rows[0]["CertFileLocation"].ToString() : null;
                string certPassword = configurationData.Configuration.Rows[0]["CertPassword"].ToString().Length> 0 ?
                                configurationData.Configuration.Rows[0]["CertPassword"].ToString() : null;
                string certFindKey = configurationData.Configuration.Rows[0]["CertFindKey"].ToString();
                bool signResponse = this.rbSignResponse.Checked;
                bool signAssertion = this.rbSignAssertion.Checked;
                SigningHelper.SignatureType signatureType = SigningHelper.SignatureType.Response;
                if (signAssertion) {
                    signatureType = SigningHelper.SignatureType.Assertion;
                }
                //if (
                // Get SAML Post Value
                if (rb_v1.Checked) {
                    postData = String.Format("SAMLResponse={0}&TARGET={1}",
                        System.Web.HttpUtility.UrlEncode(
                        davidsp8.common.Security.Saml11.SamlHelper.GetPostSamlResponse(txtRecipient.Text,
                            txtIssuer.Text, txtDomain.Text, txtSubject.Text,
                            storeLocation, storeName, findType,
                            certFileLocation, certPassword, certFindKey,
                            attributes, signatureType)),
                        txtTarget.Text);
                }
                if (rb_v2.Checked) {
                    postData = String.Format("SAMLResponse={0}&RelayState={1}",
                        System.Web.HttpUtility.UrlEncode(
                        davidsp8.common.Security.Saml20.SamlHelper.GetPostSamlResponse(txtRecipient.Text,
                            txtIssuer.Text, txtDomain.Text, txtSubject.Text,
                            storeLocation, storeName, findType,
                            certFileLocation, certPassword, certFindKey,
                            attributes, signatureType)),
                        System.Web.HttpUtility.UrlEncode(txtTarget.Text));
                }

                Logger.DebugFormat(
                    "PostData = {0}", postData);
                
                webBrowser1.Navigate(this.txtRecipient.Text, "_self", 
                    Encoding.UTF8.GetBytes(postData),
                    "Content-Type: application/x-www-form-urlencoded");
                
                webBrowser1.Visible = true;
                webBrowser1.BringToFront();
                btnShowBrowser.Text = "Hide Browser";

            } catch (UriFormatException ex) {
                MessageBox.Show(ex.Message);
            } catch (Exception ex) {
                Logger.Error(ex.Message, ex);
                MessageBox.Show(ex.Message);
            } finally {
                this.Cursor = Cursors.Default;
            }

        }
        /// <summary>
        /// Form Load - Initialize Configuration
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void frmMain_Load(object sender, EventArgs e) {
            log4net.Config.XmlConfigurator.Configure(
                new FileInfo(System.Environment.CurrentDirectory +
                    @"\log4net.config"));
            if (File.Exists(configFileName)) {
                this.configurationData.ReadXml(configFileName);
                updateFormFromConfigurationFile();
            } else {
                this.configurationData.Configuration.AddConfigurationRow(
                    this.configurationData.Configuration.NewConfigurationRow());
            }
        }
        /// <summary>
        /// Select Certificate
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnSelectCertficate_Click(object sender, EventArgs e) {
            frmSelectCertificate cert = new frmSelectCertificate(configurationData);
            cert.ShowDialog(this);
            if (cert.DialogResult == DialogResult.OK) {
                this.lblCertificateFriendlyName.Text =
                    configurationData.Configuration.Rows[0]["CertFriendlyName"].ToString();
            }
        }
        /// <summary>
        /// Save Configuration
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnSave_Click(object sender, EventArgs e) {
            updateConfigurationFileFromForm();
            saveFileDialog1.OverwritePrompt = true;
            saveFileDialog1.Filter = "Xml files (*.xml)|*.xml|All files (*.*)|*.*";
            if (saveFileDialog1.ShowDialog() == DialogResult.OK) {
                configurationData.WriteXml(saveFileDialog1.FileName);

            }
        }
        /// <summary>
        /// Form close - Update Configuration from Form values
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void frmMain_FormClosing(object sender, FormClosingEventArgs e) {
            updateConfigurationFileFromForm();
            configurationData.WriteXml(configFileName);
        }
        /// <summary>
        /// Open another configuration
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnOpen_Click(object sender, EventArgs e) {
            openFileDialog1.Filter = "Xml files (*.xml)|*.xml|All files (*.*)|*.*";
            if (openFileDialog1.ShowDialog() == DialogResult.OK) {
                configurationData.Clear();
                configurationData.ReadXml(openFileDialog1.FileName);
                updateFormFromConfigurationFile();
            }

        }

        private void btnShowBrowser_Click(object sender, EventArgs e) {
            switch (webBrowser1.Visible) {
                case true:
                    {
                        if (webBrowser1.Document.Cookie != null) {
                            for (int i = 0; i <webBrowser1.Document.Cookie.Length; i++) {
                                webBrowser1.Document.Cookie.Remove(i);
                            }
                        }

                        webBrowser1.Visible = false;

                        btnShowBrowser.Text = "Show Browser";
                        break;
                    }
                case false: {
                        webBrowser1.Visible = true;
                        webBrowser1.BringToFront();
                        btnShowBrowser.Text = "Hide Browser";
                        break;
                    }
            }
        }
    }
}