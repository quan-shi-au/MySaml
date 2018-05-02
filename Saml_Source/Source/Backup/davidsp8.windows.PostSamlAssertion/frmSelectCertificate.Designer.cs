namespace davidsp8.windows.PostSamlAssertion {
    partial class frmSelectCertificate {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing) {
            if (disposing && (components != null)) {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent() {
            this.lblCertificateFileLocation = new System.Windows.Forms.Label();
            this.lblPassword = new System.Windows.Forms.Label();
            this.btnSelect = new System.Windows.Forms.Button();
            this.lblStoreLocation = new System.Windows.Forms.Label();
            this.lblStoreName = new System.Windows.Forms.Label();
            this.cboxStoreLocation = new System.Windows.Forms.ComboBox();
            this.lblFindMethod = new System.Windows.Forms.Label();
            this.cboxStoreName = new System.Windows.Forms.ComboBox();
            this.cboxFindMethod = new System.Windows.Forms.ComboBox();
            this.txtPassword = new System.Windows.Forms.TextBox();
            this.txtCertLocation = new System.Windows.Forms.TextBox();
            this.lblFindValue = new System.Windows.Forms.Label();
            this.txtFindValue = new System.Windows.Forms.TextBox();
            this.btnOk = new System.Windows.Forms.Button();
            this.btnCancel = new System.Windows.Forms.Button();
            this.openFileDialog1 = new System.Windows.Forms.OpenFileDialog();
            this.SuspendLayout();
            // 
            // lblCertificateFileLocation
            // 
            this.lblCertificateFileLocation.AutoSize = true;
            this.lblCertificateFileLocation.Location = new System.Drawing.Point(10, 16);
            this.lblCertificateFileLocation.Name = "lblCertificateFileLocation";
            this.lblCertificateFileLocation.Size = new System.Drawing.Size(67, 13);
            this.lblCertificateFileLocation.TabIndex = 0;
            this.lblCertificateFileLocation.Text = "File Location";
            // 
            // lblPassword
            // 
            this.lblPassword.AutoSize = true;
            this.lblPassword.Location = new System.Drawing.Point(24, 45);
            this.lblPassword.Name = "lblPassword";
            this.lblPassword.Size = new System.Drawing.Size(53, 13);
            this.lblPassword.TabIndex = 1;
            this.lblPassword.Text = "Password";
            // 
            // btnSelect
            // 
            this.btnSelect.Location = new System.Drawing.Point(416, 11);
            this.btnSelect.Name = "btnSelect";
            this.btnSelect.Size = new System.Drawing.Size(24, 23);
            this.btnSelect.TabIndex = 1;
            this.btnSelect.Text = "...";
            this.btnSelect.UseVisualStyleBackColor = true;
            this.btnSelect.Click += new System.EventHandler(this.btnSelect_Click);
            // 
            // lblStoreLocation
            // 
            this.lblStoreLocation.AutoSize = true;
            this.lblStoreLocation.Location = new System.Drawing.Point(2, 74);
            this.lblStoreLocation.Name = "lblStoreLocation";
            this.lblStoreLocation.Size = new System.Drawing.Size(76, 13);
            this.lblStoreLocation.TabIndex = 3;
            this.lblStoreLocation.Text = "Store Location";
            // 
            // lblStoreName
            // 
            this.lblStoreName.AutoSize = true;
            this.lblStoreName.Location = new System.Drawing.Point(13, 103);
            this.lblStoreName.Name = "lblStoreName";
            this.lblStoreName.Size = new System.Drawing.Size(63, 13);
            this.lblStoreName.TabIndex = 4;
            this.lblStoreName.Text = "Store Name";
            // 
            // cboxStoreLocation
            // 
            this.cboxStoreLocation.FormattingEnabled = true;
            this.cboxStoreLocation.Items.AddRange(new object[] {
            "CurrentUser",
            "LocalMachine"});
            this.cboxStoreLocation.Location = new System.Drawing.Point(85, 70);
            this.cboxStoreLocation.Name = "cboxStoreLocation";
            this.cboxStoreLocation.Size = new System.Drawing.Size(171, 21);
            this.cboxStoreLocation.TabIndex = 3;
            // 
            // lblFindMethod
            // 
            this.lblFindMethod.AutoSize = true;
            this.lblFindMethod.Location = new System.Drawing.Point(11, 132);
            this.lblFindMethod.Name = "lblFindMethod";
            this.lblFindMethod.Size = new System.Drawing.Size(66, 13);
            this.lblFindMethod.TabIndex = 6;
            this.lblFindMethod.Text = "Find Method";
            // 
            // cboxStoreName
            // 
            this.cboxStoreName.FormattingEnabled = true;
            this.cboxStoreName.Items.AddRange(new object[] {
            "AddressBook",
            "AuthRoot",
            "CertificateAuthority",
            "Disallowed",
            "My",
            "Root",
            "TrustedPeople",
            "TrustedPublisher"});
            this.cboxStoreName.Location = new System.Drawing.Point(85, 99);
            this.cboxStoreName.Name = "cboxStoreName";
            this.cboxStoreName.Size = new System.Drawing.Size(171, 21);
            this.cboxStoreName.TabIndex = 4;
            // 
            // cboxFindMethod
            // 
            this.cboxFindMethod.FormattingEnabled = true;
            this.cboxFindMethod.Items.AddRange(new object[] {
            "FindByThumbprint ",
            "FindBySubjectName",
            "FindBySubjectDistinguishedName",
            "FindByIssuerName",
            "FindByIssuerDistinguishedName",
            "FindBySerialNumber",
            "FindByTimeValid",
            "FindByTimeNotYetValid",
            "FindByTimeExpired",
            "FindByTemplateName",
            "FindByApplicationPolicy",
            "FindByCertificatePolicy",
            "FindByExtension",
            "FindByKeyUsage",
            "FindBySubjectKeyIdentifier"});
            this.cboxFindMethod.Location = new System.Drawing.Point(85, 128);
            this.cboxFindMethod.Name = "cboxFindMethod";
            this.cboxFindMethod.Size = new System.Drawing.Size(171, 21);
            this.cboxFindMethod.TabIndex = 5;
            // 
            // txtPassword
            // 
            this.txtPassword.Location = new System.Drawing.Point(85, 41);
            this.txtPassword.Name = "txtPassword";
            this.txtPassword.PasswordChar = '*';
            this.txtPassword.Size = new System.Drawing.Size(171, 20);
            this.txtPassword.TabIndex = 2;
            // 
            // txtCertLocation
            // 
            this.txtCertLocation.Location = new System.Drawing.Point(85, 12);
            this.txtCertLocation.Name = "txtCertLocation";
            this.txtCertLocation.Size = new System.Drawing.Size(325, 20);
            this.txtCertLocation.TabIndex = 0;
            // 
            // lblFindValue
            // 
            this.lblFindValue.AutoSize = true;
            this.lblFindValue.Location = new System.Drawing.Point(20, 161);
            this.lblFindValue.Name = "lblFindValue";
            this.lblFindValue.Size = new System.Drawing.Size(57, 13);
            this.lblFindValue.TabIndex = 11;
            this.lblFindValue.Text = "Find Value";
            // 
            // txtFindValue
            // 
            this.txtFindValue.Location = new System.Drawing.Point(85, 157);
            this.txtFindValue.Name = "txtFindValue";
            this.txtFindValue.Size = new System.Drawing.Size(325, 20);
            this.txtFindValue.TabIndex = 6;
            // 
            // btnOk
            // 
            this.btnOk.Location = new System.Drawing.Point(337, 186);
            this.btnOk.Name = "btnOk";
            this.btnOk.Size = new System.Drawing.Size(75, 23);
            this.btnOk.TabIndex = 8;
            this.btnOk.Text = "&Ok";
            this.btnOk.UseVisualStyleBackColor = true;
            this.btnOk.Click += new System.EventHandler(this.btnOk_Click);
            // 
            // btnCancel
            // 
            this.btnCancel.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            this.btnCancel.Location = new System.Drawing.Point(253, 186);
            this.btnCancel.Name = "btnCancel";
            this.btnCancel.Size = new System.Drawing.Size(75, 23);
            this.btnCancel.TabIndex = 7;
            this.btnCancel.Text = "Ca&ncel";
            this.btnCancel.UseVisualStyleBackColor = true;
            this.btnCancel.Click += new System.EventHandler(this.btnCancel_Click);
            // 
            // frmSelectCertificate
            // 
            this.AcceptButton = this.btnOk;
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.CancelButton = this.btnCancel;
            this.ClientSize = new System.Drawing.Size(446, 221);
            this.ControlBox = false;
            this.Controls.Add(this.btnCancel);
            this.Controls.Add(this.btnOk);
            this.Controls.Add(this.txtFindValue);
            this.Controls.Add(this.lblFindValue);
            this.Controls.Add(this.txtCertLocation);
            this.Controls.Add(this.txtPassword);
            this.Controls.Add(this.cboxFindMethod);
            this.Controls.Add(this.cboxStoreName);
            this.Controls.Add(this.lblFindMethod);
            this.Controls.Add(this.cboxStoreLocation);
            this.Controls.Add(this.lblStoreName);
            this.Controls.Add(this.lblStoreLocation);
            this.Controls.Add(this.btnSelect);
            this.Controls.Add(this.lblPassword);
            this.Controls.Add(this.lblCertificateFileLocation);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "frmSelectCertificate";
            this.ShowInTaskbar = false;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.Text = "Select Certificate";
            this.Load += new System.EventHandler(this.frmSelectCertificate_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label lblCertificateFileLocation;
        private System.Windows.Forms.Label lblPassword;
        private System.Windows.Forms.Button btnSelect;
        private System.Windows.Forms.Label lblStoreLocation;
        private System.Windows.Forms.Label lblStoreName;
        private System.Windows.Forms.ComboBox cboxStoreLocation;
        private System.Windows.Forms.Label lblFindMethod;
        private System.Windows.Forms.ComboBox cboxStoreName;
        private System.Windows.Forms.ComboBox cboxFindMethod;
        private System.Windows.Forms.TextBox txtPassword;
        private System.Windows.Forms.TextBox txtCertLocation;
        private System.Windows.Forms.Label lblFindValue;
        private System.Windows.Forms.TextBox txtFindValue;
        private System.Windows.Forms.Button btnOk;
        private System.Windows.Forms.Button btnCancel;
        private System.Windows.Forms.OpenFileDialog openFileDialog1;
    }
}