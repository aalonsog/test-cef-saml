var saml2 = require('./saml-lib');
var fs = require('fs');
var express = require('express');
var path = require('path');
var app = express();
var request = require('request');
var bodyParser = require('body-parser');
app.use(bodyParser.urlencoded({ extended: false }))

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
 
// Create service provider
var sp_options = {
  entity_id: "http://yosi.dit.upm.es/metadata",
  private_key: fs.readFileSync("certs/key-file.pem").toString(),
  certificate: fs.readFileSync("certs/cert-file.crt").toString(),
  assert_endpoint: "http://yosi.dit.upm.es/ReturnPage",
  sign_get_request: true,
  nameid_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
  auth_context: { comparison: "minimum", class_refs: ["http://eidas.europa.eu/LoA/low"] },
  force_authn: true,
  organization: 'Universidad Politecnica de Madrid',
  contact: 'Alvaro Alonso'
};

var sp = new saml2.ServiceProvider(sp_options);
 
// Create identity provider
var idp_options = {
  sso_login_url: "https://se-eidas.redsara.es/EidasNode/ServiceProvider",
  sso_logout_url: "https://idp.example.com/logout",
  certificates: [fs.readFileSync("certs/cert-file1.crt").toString(), fs.readFileSync("certs/cert-file2.crt").toString()]
};
var idp = new saml2.IdentityProvider(idp_options);
 
// ------ Define express endpoints ------
 
// Endpoint to retrieve metadata
app.get("/metadata", function(req, res) {
  res.type('application/xml');
  res.send(sp.create_metadata());
});
 
// Starting point for login
app.get("/", function(req, res) {
  var xml = sp.create_authn_request_xml(idp, {
    extensions: {
      'eidas:SPType': 'public',
      'eidas:RequestedAttributes': [
        {'eidas:RequestedAttribute': {
          '@FriendlyName': 'LegalName',
          '@Name': 'http://eidas.europa.eu/attributes/legalperson/LegalName',
          '@NameFormat': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          '@isRequired': 'true'
        }},
        {'eidas:RequestedAttribute': {
          '@FriendlyName': 'LegalPersonIdentifier',
          '@Name': 'http://eidas.europa.eu/attributes/legalperson/LegalPersonIdentifier',
          '@NameFormat': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          '@isRequired': 'true'
        }},
        {'eidas:RequestedAttribute': {
          '@FriendlyName': 'FamilyName',
          '@Name': 'http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName',
          '@NameFormat': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          '@isRequired': 'true'
        }},
        {'eidas:RequestedAttribute': {
          '@FriendlyName': 'FirstName',
          '@Name': 'http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName',
          '@NameFormat': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          '@isRequired': 'true'
        }},
        {'eidas:RequestedAttribute': {
          '@FriendlyName': 'DateOfBirth',
          '@Name': 'http://eidas.europa.eu/attributes/naturalperson/DateOfBirth',
          '@NameFormat': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          '@isRequired': 'true'
        }},
        {'eidas:RequestedAttribute': {
          '@FriendlyName': 'PersonIdentifier',
          '@Name': 'http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier',
          '@NameFormat': 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
          '@isRequired': 'true'
        }}]
      }
  });
  res.render('index', {body:xml});
});

app.post("/login", function(req, res) {
  // sp.create_login_request_url(idp, {}, function(err, login_url, request_id) {
  //   if (err != null)
  //     return res.send(500);
  //   console.log('*******', login_url);
  //   res.redirect(login_url);
  // });
  res.redirect(307, 'https://se-eidas.redsara.es/EidasNode/ServiceProvider');
});
 
// Assert endpoint for when login completes
app.post("/ReturnPage", function(req, res) {
  var options = {request_body: req.body};
  sp.post_assert(idp, options, function(err, saml_response) {
    if (err != null)
      return res.send(500);
 
    // Save name_id and session_index for logout
    // Note:  In practice these should be saved in the user session, not globally.
    name_id = saml_response.user.name_id;
    session_index = saml_response.user.session_index;
 
    res.send("Hello #{saml_response.user.name_id}!");
  });
});
 
// Starting point for logout
app.get("/logout", function(req, res) {
  var options = {
    name_id: name_id,
    session_index: session_index
  };
 
  sp.create_logout_request_url(idp, options, function(err, logout_url) {
    if (err != null)
      return res.send(500);
    res.redirect(logout_url);
  });
});
 
app.listen(3000);