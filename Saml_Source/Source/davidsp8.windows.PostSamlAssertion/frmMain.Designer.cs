namespace davidsp8.windows.PostSamlAssertion {
    partial class frmMain {
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
            this.components = new System.ComponentModel.Container();
            this.btnPostAssertion = new System.Windows.Forms.Button();
            this.txtRecipient = new System.Windows.Forms.TextBox();
            this.lblRecipient = new System.Windows.Forms.Label();
            this.txtTarget = new System.Windows.Forms.TextBox();
            this.lblTarget = new System.Windows.Forms.Label();
            this.txtSubject = new System.Windows.Forms.TextBox();
            this.lblSubject = new System.Windows.Forms.Label();
            this.btnSave = new System.Windows.Forms.Button();
            this.btnOpen = new System.Windows.Forms.Button();
            this.lblCertificate = new System.Windows.Forms.Label();
            this.lblCertificateFriendlyName = new System.Windows.Forms.Label();
            this.btnSelectCertficate = new System.Windows.Forms.Button();
            this.lblAttributes = new System.Windows.Forms.Label();
            this.dataGridView1 = new System.Windows.Forms.DataGridView();
            this.configIDDataGridViewTextBoxColumn = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.sequenceDataGridViewTextBoxColumn = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.nameDataGridViewTextBoxColumn = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.valueDataGridViewTextBoxColumn = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.attributesBindingSource = new System.Windows.Forms.BindingSource(this.components);
            this.configurationDataBindingSource = new System.Windows.Forms.BindingSource(this.components);
            this.configurationData = new davidsp8.windows.PostSamlAssertion.ConfigurationData();
            this.saveFileDialog1 = new System.Windows.Forms.SaveFileDialog();
            this.openFileDialog1 = new System.Windows.Forms.OpenFileDialog();
            this.lblIssuer = new System.Windows.Forms.Label();
            this.txtIssuer = new System.Windows.Forms.TextBox();
            this.lblNameQualifier = new System.Windows.Forms.Label();
            this.txtDomain = new System.Windows.Forms.TextBox();
            this.rb_v2 = new System.Windows.Forms.RadioButton();
            this.rb_v1 = new System.Windows.Forms.RadioButton();
            this.webBrowser1 = new System.Windows.Forms.WebBrowser();
            this.btnShowBrowser = new System.Windows.Forms.Button();
            this.rbSignResponse = new System.Windows.Forms.RadioButton();
            this.rbSignAssertion = new System.Windows.Forms.RadioButton();
            this.gbSigningOptions = new System.Windows.Forms.GroupBox();
            ((System.ComponentModel.ISupportInitialize)(this.dataGridView1)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.attributesBindingSource)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.configurationDataBindingSource)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.configurationData)).BeginInit();
            this.gbSigningOptions.SuspendLayout();
            this.SuspendLayout();
            // 
            // btnPostAssertion
            // 
            this.btnPostAssertion.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnPostAssertion.Location = new System.Drawing.Point(385, 407);
            this.btnPostAssertion.Name = "btnPostAssertion";
            this.btnPostAssertion.Size = new System.Drawing.Size(102, 23);
            this.btnPostAssertion.TabIndex = 0;
            this.btnPostAssertion.Text = "Post Assertion";
            this.btnPostAssertion.UseVisualStyleBackColor = true;
            this.btnPostAssertion.Click += new System.EventHandler(this.btnPostAssertion_Click);
            // 
            // txtRecipient
            // 
            this.txtRecipient.Location = new System.Drawing.Point(84, 55);
            this.txtRecipient.Name = "txtRecipient";
            this.txtRecipient.Size = new System.Drawing.Size(362, 20);
            this.txtRecipient.TabIndex = 2;
            // 
            // lblRecipient
            // 
            this.lblRecipient.AutoSize = true;
            this.lblRecipient.Location = new System.Drawing.Point(29, 58);
            this.lblRecipient.Name = "lblRecipient";
            this.lblRecipient.Size = new System.Drawing.Size(52, 13);
            this.lblRecipient.TabIndex = 3;
            this.lblRecipient.Text = "Recipient";
            // 
            // txtTarget
            // 
            this.txtTarget.Location = new System.Drawing.Point(84, 82);
            this.txtTarget.Name = "txtTarget";
            this.txtTarget.Size = new System.Drawing.Size(362, 20);
            this.txtTarget.TabIndex = 4;
            // 
            // lblTarget
            // 
            this.lblTarget.AutoSize = true;
            this.lblTarget.Location = new System.Drawing.Point(43, 86);
            this.lblTarget.Name = "lblTarget";
            this.lblTarget.Size = new System.Drawing.Size(38, 13);
            this.lblTarget.TabIndex = 5;
            this.lblTarget.Text = "Target";
            // 
            // txtSubject
            // 
            this.txtSubject.Location = new System.Drawing.Point(84, 136);
            this.txtSubject.Name = "txtSubject";
            this.txtSubject.Size = new System.Drawing.Size(362, 20);
            this.txtSubject.TabIndex = 6;
            // 
            // lblSubject
            // 
            this.lblSubject.AutoSize = true;
            this.lblSubject.Location = new System.Drawing.Point(38, 140);
            this.lblSubject.Name = "lblSubject";
            this.lblSubject.Size = new System.Drawing.Size(43, 13);
            this.lblSubject.TabIndex = 7;
            this.lblSubject.Text = "Subject";
            // 
            // btnSave
            // 
            this.btnSave.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnSave.Location = new System.Drawing.Point(20, 407);
            this.btnSave.Name = "btnSave";
            this.btnSave.Size = new System.Drawing.Size(75, 23);
            this.btnSave.TabIndex = 8;
            this.btnSave.Text = "&Save Config";
            this.btnSave.UseVisualStyleBackColor = true;
            this.btnSave.Click += new System.EventHandler(this.btnSave_Click);
            // 
            // btnOpen
            // 
            this.btnOpen.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnOpen.Location = new System.Drawing.Point(104, 407);
            this.btnOpen.Name = "btnOpen";
            this.btnOpen.Size = new System.Drawing.Size(75, 23);
            this.btnOpen.TabIndex = 9;
            this.btnOpen.Text = "&Open Config";
            this.btnOpen.UseVisualStyleBackColor = true;
            this.btnOpen.Click += new System.EventHandler(this.btnOpen_Click);
            // 
            // lblCertificate
            // 
            this.lblCertificate.AutoSize = true;
            this.lblCertificate.Location = new System.Drawing.Point(27, 163);
            this.lblCertificate.Name = "lblCertificate";
            this.lblCertificate.Size = new System.Drawing.Size(54, 13);
            this.lblCertificate.TabIndex = 10;
            this.lblCertificate.Text = "Certificate";
            // 
            // lblCertificateFriendlyName
            // 
            this.lblCertificateFriendlyName.AutoSize = true;
            this.lblCertificateFriendlyName.Location = new System.Drawing.Point(84, 163);
            this.lblCertificateFriendlyName.Name = "lblCertificateFriendlyName";
            this.lblCertificateFriendlyName.Size = new System.Drawing.Size(39, 13);
            this.lblCertificateFriendlyName.TabIndex = 11;
            this.lblCertificateFriendlyName.Text = "[None]";
            // 
            // btnSelectCertficate
            // 
            this.btnSelectCertficate.Location = new System.Drawing.Point(450, 158);
            this.btnSelectCertficate.Name = "btnSelectCertficate";
            this.btnSelectCertficate.Size = new System.Drawing.Size(24, 22);
            this.btnSelectCertficate.TabIndex = 12;
            this.btnSelectCertficate.Text = "...";
            this.btnSelectCertficate.UseVisualStyleBackColor = true;
            this.btnSelectCertficate.Click += new System.EventHandler(this.btnSelectCertficate_Click);
            // 
            // lblAttributes
            // 
            this.lblAttributes.AutoSize = true;
            this.lblAttributes.Location = new System.Drawing.Point(29, 184);
            this.lblAttributes.Name = "lblAttributes";
            this.lblAttributes.Size = new System.Drawing.Size(51, 13);
            this.lblAttributes.TabIndex = 13;
            this.lblAttributes.Text = "Attributes";
            // 
            // dataGridView1
            // 
            this.dataGridView1.AutoGenerateColumns = false;
            this.dataGridView1.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.dataGridView1.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.configIDDataGridViewTextBoxColumn,
            this.sequenceDataGridViewTextBoxColumn,
            this.nameDataGridViewTextBoxColumn,
            this.valueDataGridViewTextBoxColumn});
            this.dataGridView1.DataSource = this.attributesBindingSource;
            this.dataGridView1.Location = new System.Drawing.Point(84, 184);
            this.dataGridView1.Name = "dataGridView1";
            this.dataGridView1.Size = new System.Drawing.Size(359, 163);
            this.dataGridView1.TabIndex = 14;
            // 
            // configIDDataGridViewTextBoxColumn
            // 
            this.configIDDataGridViewTextBoxColumn.DataPropertyName = "ConfigID";
            this.configIDDataGridViewTextBoxColumn.HeaderText = "ConfigID";
            this.configIDDataGridViewTextBoxColumn.Name = "configIDDataGridViewTextBoxColumn";
            this.configIDDataGridViewTextBoxColumn.Visible = false;
            // 
            // sequenceDataGridViewTextBoxColumn
            // 
            this.sequenceDataGridViewTextBoxColumn.DataPropertyName = "Sequence";
            this.sequenceDataGridViewTextBoxColumn.HeaderText = "Sequence";
            this.sequenceDataGridViewTextBoxColumn.Name = "sequenceDataGridViewTextBoxColumn";
            this.sequenceDataGridViewTextBoxColumn.Visible = false;
            // 
            // nameDataGridViewTextBoxColumn
            // 
            this.nameDataGridViewTextBoxColumn.DataPropertyName = "Name";
            this.nameDataGridViewTextBoxColumn.HeaderText = "Name";
            this.nameDataGridViewTextBoxColumn.Name = "nameDataGridViewTextBoxColumn";
            // 
            // valueDataGridViewTextBoxColumn
            // 
            this.valueDataGridViewTextBoxColumn.DataPropertyName = "Value";
            this.valueDataGridViewTextBoxColumn.HeaderText = "Value";
            this.valueDataGridViewTextBoxColumn.Name = "valueDataGridViewTextBoxColumn";
            // 
            // attributesBindingSource
            // 
            this.attributesBindingSource.DataMember = "Attributes";
            this.attributesBindingSource.DataSource = this.configurationDataBindingSource;
            // 
            // configurationDataBindingSource
            // 
            this.configurationDataBindingSource.DataSource = this.configurationData;
            this.configurationDataBindingSource.Position = 0;
            // 
            // configurationData
            // 
            this.configurationData.DataSetName = "ConfigurationData";
            this.configurationData.SchemaSerializationMode = System.Data.SchemaSerializationMode.IncludeSchema;
            // 
            // openFileDialog1
            // 
            this.openFileDialog1.FileName = "openFileDialog1";
            // 
            // lblIssuer
            // 
            this.lblIssuer.AutoSize = true;
            this.lblIssuer.Location = new System.Drawing.Point(44, 34);
            this.lblIssuer.Name = "lblIssuer";
            this.lblIssuer.Size = new System.Drawing.Size(35, 13);
            this.lblIssuer.TabIndex = 15;
            this.lblIssuer.Text = "Issuer";
            // 
            // txtIssuer
            // 
            this.txtIssuer.Location = new System.Drawing.Point(84, 28);
            this.txtIssuer.Name = "txtIssuer";
            this.txtIssuer.Size = new System.Drawing.Size(362, 20);
            this.txtIssuer.TabIndex = 16;
            // 
            // lblNameQualifier
            // 
            this.lblNameQualifier.AutoSize = true;
            this.lblNameQualifier.Location = new System.Drawing.Point(36, 113);
            this.lblNameQualifier.Name = "lblNameQualifier";
            this.lblNameQualifier.Size = new System.Drawing.Size(43, 13);
            this.lblNameQualifier.TabIndex = 17;
            this.lblNameQualifier.Text = "Domain";
            // 
            // txtDomain
            // 
            this.txtDomain.Location = new System.Drawing.Point(84, 109);
            this.txtDomain.Name = "txtDomain";
            this.txtDomain.Size = new System.Drawing.Size(362, 20);
            this.txtDomain.TabIndex = 5;
            // 
            // rb_v2
            // 
            this.rb_v2.AutoSize = true;
            this.rb_v2.Location = new System.Drawing.Point(169, 5);
            this.rb_v2.Name = "rb_v2";
            this.rb_v2.Size = new System.Drawing.Size(78, 17);
            this.rb_v2.TabIndex = 21;
            this.rb_v2.Text = "Version 2.0";
            this.rb_v2.UseVisualStyleBackColor = true;
            // 
            // rb_v1
            // 
            this.rb_v1.AutoSize = true;
            this.rb_v1.Location = new System.Drawing.Point(85, 5);
            this.rb_v1.Name = "rb_v1";
            this.rb_v1.Size = new System.Drawing.Size(78, 17);
            this.rb_v1.TabIndex = 20;
            this.rb_v1.Text = "Version 1.1";
            this.rb_v1.UseVisualStyleBackColor = true;
            // 
            // webBrowser1
            // 
            this.webBrowser1.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)
                        | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.webBrowser1.Location = new System.Drawing.Point(0, 0);
            this.webBrowser1.MinimumSize = new System.Drawing.Size(20, 20);
            this.webBrowser1.Name = "webBrowser1";
            this.webBrowser1.Size = new System.Drawing.Size(497, 401);
            this.webBrowser1.TabIndex = 22;
            this.webBrowser1.Visible = false;
            // 
            // btnShowBrowser
            // 
            this.btnShowBrowser.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnShowBrowser.Location = new System.Drawing.Point(235, 406);
            this.btnShowBrowser.Name = "btnShowBrowser";
            this.btnShowBrowser.Size = new System.Drawing.Size(96, 23);
            this.btnShowBrowser.TabIndex = 23;
            this.btnShowBrowser.Text = "Show Browser";
            this.btnShowBrowser.UseVisualStyleBackColor = true;
            this.btnShowBrowser.Click += new System.EventHandler(this.btnShowBrowser_Click);
            // 
            // rbSignResponse
            // 
            this.rbSignResponse.AutoSize = true;
            this.rbSignResponse.Checked = true;
            this.rbSignResponse.Location = new System.Drawing.Point(6, 18);
            this.rbSignResponse.Name = "rbSignResponse";
            this.rbSignResponse.Size = new System.Drawing.Size(97, 17);
            this.rbSignResponse.TabIndex = 24;
            this.rbSignResponse.TabStop = true;
            this.rbSignResponse.Text = "Sign Response";
            this.rbSignResponse.UseVisualStyleBackColor = true;
            // 
            // rbSignAssertion
            // 
            this.rbSignAssertion.AutoSize = true;
            this.rbSignAssertion.Location = new System.Drawing.Point(118, 18);
            this.rbSignAssertion.Name = "rbSignAssertion";
            this.rbSignAssertion.Size = new System.Drawing.Size(92, 17);
            this.rbSignAssertion.TabIndex = 25;
            this.rbSignAssertion.Text = "Sign Assertion";
            this.rbSignAssertion.UseVisualStyleBackColor = true;
            // 
            // gbSigningOptions
            // 
            this.gbSigningOptions.Controls.Add(this.rbSignResponse);
            this.gbSigningOptions.Controls.Add(this.rbSignAssertion);
            this.gbSigningOptions.Location = new System.Drawing.Point(84, 353);
            this.gbSigningOptions.Name = "gbSigningOptions";
            this.gbSigningOptions.Size = new System.Drawing.Size(358, 47);
            this.gbSigningOptions.TabIndex = 26;
            this.gbSigningOptions.TabStop = false;
            this.gbSigningOptions.Text = "Signing Options";
            // 
            // frmMain
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(497, 438);
            this.Controls.Add(this.gbSigningOptions);
            this.Controls.Add(this.btnShowBrowser);
            this.Controls.Add(this.rb_v2);
            this.Controls.Add(this.rb_v1);
            this.Controls.Add(this.txtDomain);
            this.Controls.Add(this.lblNameQualifier);
            this.Controls.Add(this.txtIssuer);
            this.Controls.Add(this.lblIssuer);
            this.Controls.Add(this.dataGridView1);
            this.Controls.Add(this.lblAttributes);
            this.Controls.Add(this.btnSelectCertficate);
            this.Controls.Add(this.lblCertificateFriendlyName);
            this.Controls.Add(this.lblCertificate);
            this.Controls.Add(this.btnOpen);
            this.Controls.Add(this.btnSave);
            this.Controls.Add(this.lblSubject);
            this.Controls.Add(this.txtSubject);
            this.Controls.Add(this.lblTarget);
            this.Controls.Add(this.txtTarget);
            this.Controls.Add(this.lblRecipient);
            this.Controls.Add(this.txtRecipient);
            this.Controls.Add(this.btnPostAssertion);
            this.Controls.Add(this.webBrowser1);
            this.Name = "frmMain";
            this.Text = "Post Saml Assertion";
            this.Load += new System.EventHandler(this.frmMain_Load);
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.frmMain_FormClosing);
            ((System.ComponentModel.ISupportInitialize)(this.dataGridView1)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.attributesBindingSource)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.configurationDataBindingSource)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.configurationData)).EndInit();
            this.gbSigningOptions.ResumeLayout(false);
            this.gbSigningOptions.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button btnPostAssertion;
        private System.Windows.Forms.TextBox txtRecipient;
        private System.Windows.Forms.Label lblRecipient;
        private System.Windows.Forms.TextBox txtTarget;
        private System.Windows.Forms.Label lblTarget;
        private System.Windows.Forms.TextBox txtSubject;
        private System.Windows.Forms.Label lblSubject;
        private System.Windows.Forms.Button btnSave;
        private System.Windows.Forms.Button btnOpen;
        private System.Windows.Forms.Label lblCertificate;
        private System.Windows.Forms.Label lblCertificateFriendlyName;
        private System.Windows.Forms.Button btnSelectCertficate;
        private System.Windows.Forms.Label lblAttributes;
        private System.Windows.Forms.DataGridView dataGridView1;
        private System.Windows.Forms.DataGridViewTextBoxColumn configIDDataGridViewTextBoxColumn;
        private System.Windows.Forms.DataGridViewTextBoxColumn sequenceDataGridViewTextBoxColumn;
        private System.Windows.Forms.DataGridViewTextBoxColumn nameDataGridViewTextBoxColumn;
        private System.Windows.Forms.DataGridViewTextBoxColumn valueDataGridViewTextBoxColumn;
        private System.Windows.Forms.BindingSource attributesBindingSource;
        private System.Windows.Forms.BindingSource configurationDataBindingSource;
        private ConfigurationData configurationData;
        private System.Windows.Forms.SaveFileDialog saveFileDialog1;
        private System.Windows.Forms.OpenFileDialog openFileDialog1;
        private System.Windows.Forms.Label lblIssuer;
        private System.Windows.Forms.TextBox txtIssuer;
        private System.Windows.Forms.Label lblNameQualifier;
        private System.Windows.Forms.TextBox txtDomain;
        private System.Windows.Forms.RadioButton rb_v2;
        private System.Windows.Forms.RadioButton rb_v1;
        private System.Windows.Forms.WebBrowser webBrowser1;
        private System.Windows.Forms.Button btnShowBrowser;
        private System.Windows.Forms.RadioButton rbSignResponse;
        private System.Windows.Forms.RadioButton rbSignAssertion;
        private System.Windows.Forms.GroupBox gbSigningOptions;
    }
}

