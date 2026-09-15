# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
import datetime
import json
from flask import session
from misc import (
    calculate_age,
    doctype2credential,
    doctype2credentialSDJWT,
    getIssuerFilledAttributes,
    getIssuerFilledAttributesSDJWT,
    getMandatoryAttributes,
    getMandatoryAttributesSDJWT,
    getNamespaces,
    getOptionalAttributes,
    getOptionalAttributesSDJWT,
)
from redirect_func import json_post
import base64
from flask import session
from misc import calculate_age
from redirect_func import json_post
from app import oidc_metadata
from app import session_manager
from app import CONFIGURATION
from formatter_func import mdocFormatter, sdjwtFormatter


def dynamic_formatter(format, scope, form_data, device_publickey, session_id):

    current_session = session_manager.get_session(session_id=session_id)

    if (
        scope == "eu.europa.ec.eudi.mdl_mdoc"
        or scope == "eu.europa.ec.eudi.aamva_mdl_mdoc"
    ):
        un_distinguishing_sign = CONFIGURATION["countries"][current_session.country]["un_distinguishing_sign"]
    else:
        un_distinguishing_sign = ""

    data, requested_credential = formatter(
        dict(form_data), un_distinguishing_sign, scope, format
    )

    r = {}

    if format == "mso_mdoc":
        base64_mdoc = mdocFormatter(
            data=data,
            credential_metadata=requested_credential,
            country=current_session.country,
            device_publickey=device_publickey,
            session_id=session_id,
        )

    elif format == "dc+sd-jwt":
        url = CONFIGURATION["service_url"] + "/formatter/sd-jwt"

        r = json_post(
            url,
            {
                "country": current_session.country,
                "credential_metadata": requested_credential,
                "scope": scope,
                "device_publickey": device_publickey,
                "data": data,
            },
        ).json()

        if not r["error_code"] == 0:
            return "Error"

    if format == "mso_mdoc":
        credential = base64_mdoc

    elif format == "dc+sd-jwt":
        credential = r["sd-jwt"]

    return credential


def formatter(data, un_distinguishing_sign, scope, format):
    today = datetime.date.today()

    requested_credential, pdata = get_requested_credential(data, scope, format, today)
    doctype_config = requested_credential["issuer_config"]
    expiry = today + datetime.timedelta(days=doctype_config["validity"])

    # Extract claim categories
    if format == "mso_mdoc":
        namescapes = getNamespaces(
            requested_credential["credential_metadata"]["claims"]
        )

        attributes_by_namespace = {}

        attributes_req = {}
        attributes_req2 = {}
        issuer_claims = {}

        for namescape in namescapes:
            attributes_by_namespace[namescape] = {
                "mandatory": getMandatoryAttributes(
                    requested_credential["credential_metadata"]["claims"], namescape
                ),
                "optional": getOptionalAttributes(
                    requested_credential["credential_metadata"]["claims"], namescape
                ),
                "issuer": getIssuerFilledAttributes(
                    requested_credential["credential_metadata"]["claims"], namescape
                ),
            }

        attributes_req = {}
        attributes_req2 = {}
        issuer_claims = {}

        for namescape in namescapes:
            attributes_req.update(attributes_by_namespace[namescape]["mandatory"])
            attributes_req2.update(attributes_by_namespace[namescape]["optional"])
            issuer_claims.update(attributes_by_namespace[namescape]["issuer"])

    else:  # "dc+sd-jwt"
        attributes_req = getMandatoryAttributesSDJWT(
            requested_credential["credential_metadata"]["claims"]
        )
        attributes_req2 = getOptionalAttributesSDJWT(
            requested_credential["credential_metadata"]["claims"]
        )
        issuer_claims = getIssuerFilledAttributesSDJWT(
            requested_credential["credential_metadata"]["claims"]
        )

    # Update special claims
    update_dates_and_special_claims(
        data,
        issuer_claims,
        un_distinguishing_sign,
        today,
        expiry,
        requested_credential,
        doctype_config,
    )

    # Normalize list and type fields
    normalize_list_and_type_fields(data, attributes_req, attributes_req2)

    # Populate pdata
    populate_pdata(
        data,
        pdata,
        format,
        namescapes if format == "mso_mdoc" else None,
        attributes_req,
        attributes_req2,
        issuer_claims,
        attributes_by_namespace=(
            attributes_by_namespace if format == "mso_mdoc" else None
        ),
    )

    return pdata, requested_credential


def get_requested_credential(data, scope, format, today):
    cred = oidc_metadata["credential_configurations_supported"][scope]

    if format == "mso_mdoc":
        # cred = doctype2credential(doctype, format)
        pdata = {}
    else:  # "dc+sd-jwt"
        # cred = doctype2credentialSDJWT(doctype, format)
        doctype_config = cred["issuer_config"]
        pdata = {
            "evidence": [
                {
                    "type": cred["vct"],
                    "source": {
                        "organization_name": doctype_config["organization_name"],
                        "organization_id": doctype_config["organization_id"],
                        "country_code": data["issuing_country"],
                    },
                }
            ],
            "claims": {},
        }
    return cred, pdata


def update_dates_and_special_claims(
    data,
    issuer_claims,
    un_distinguishing_sign,
    today,
    expiry,
    requested_credential,
    doctype_config,
):
    # Age over 18
    if "age_over_18" in issuer_claims and "birth_date" in data:
        data["age_over_18"] = calculate_age(data["birth_date"]) >= 18

    # Un-distinguishing sign
    if "un_distinguishing_sign" in issuer_claims:
        data["un_distinguishing_sign"] = un_distinguishing_sign

    # Dates
    date_fields = {
        "issuance_date": today,
        "date_of_issuance": today,
        "issue_date": today,
        "expiry_date": expiry,
        "date_of_expiry": expiry,
    }
    for field, value in date_fields.items():
        if field in issuer_claims:
            data[field] = value.strftime("%Y-%m-%d")

    # Issuing authority
    if "issuing_authority" in issuer_claims:
        if requested_credential.get("scope") == "eu.europa.ec.eudi.ehic_sd_jwt_vc":
            data["issuing_authority"] = {
                "id": doctype_config["issuing_authority_id"],
                "name": doctype_config["issuing_authority"],
            }
        else:
            data["issuing_authority"] = doctype_config["issuing_authority"]

    if "issuing_authority_unicode" in issuer_claims:
        data["issuing_authority_unicode"] = doctype_config["issuing_authority"]

    if "credential_type" in issuer_claims:
        data["credential_type"] = doctype_config["credential_type"]


def normalize_list_and_type_fields(data, attributes_req, attributes_req2):
    list_fields = [
        "places_of_work",
        "legislation",
        "employment_details",
        "competent_institution",
        "credential_holder",
        "subject",
        "residence_address",
    ]

    for field in list_fields:
        if field in attributes_req and field in data:
            if isinstance(data[field], str):
                data[field] = json.loads(data[field])
            if isinstance(data[field], list):
                data[field] = data[field][0]

        if field in attributes_req2 and field in data:
            if isinstance(data[field], str):
                data[field] = json.loads(data[field])
            if isinstance(data[field], list):
                data[field] = data[field][0]

    # Numeric conversions
    if "age_in_years" in data and isinstance(data["age_in_years"], str):
        data["age_in_years"] = int(data["age_in_years"])
    if "age_birth_year" in data and isinstance(data["age_birth_year"], str):
        data["age_birth_year"] = int(data["age_birth_year"])
    if (
        "gender" in data
        and isinstance(data["gender"], str)
        and data["gender"].isdigit()
    ):
        data["gender"] = int(data["gender"])


def populate_pdata(
    data,
    pdata,
    format,
    namescapes,
    attributes_req,
    attributes_req2,
    issuer_claims,
    attributes_by_namespace=None,
):
    if format == "mso_mdoc":
        for namescape in namescapes:
            pdata[namescape] = {}
            # Use the namespace-specific attributes
            namespace_attrs = attributes_by_namespace[namescape]
            for attr_group in (
                namespace_attrs["mandatory"],
                namespace_attrs["optional"],
                namespace_attrs["issuer"],
            ):
                for attr in attr_group:
                    if attr in data:
                        pdata[namescape][attr] = data[attr]

            # LOCAL TEST PATCH -- not upstream, applied by bind mount from
            # testdata/eudi-pid-issuer-py/patches/dynamic_func.py.
            #
            # Upstream mints only the claims this credential configuration
            # declares: the loop above walks its own configured attributes and
            # copies a value only where the key is present in `data`, so a
            # threshold the configuration does not list is accepted by the offer
            # endpoint and then silently left out of the signed credential -- no
            # error at either end, and nothing in the issued document.
            #
            # ISO 18013-5 and the EUDI age-verification profile both leave the
            # set of thresholds open, so testing the wallet against an arbitrary
            # age_over_NN needs an issuer that will mint one. The alternative was
            # enumerating every threshold in the configuration, which works but
            # advertises a hundred claims -- and the wallet renders one row per
            # advertised claim on the issuance offer screen
            # (convertClaimsToAttributes in eudi/openid4vci/client.go), making
            # the demo unusable. Widening what may be minted without widening
            # what is advertised keeps the metadata identical to staging.
            #
            # Scoped to the age-verification namespace so it cannot leak an
            # age_over_NN into a PID or mDL document, and setdefault so a
            # configured value always wins.
            if namescape == "eu.europa.ec.av.1":
                for extra, extra_value in data.items():
                    if extra.startswith("age_over_") and extra[9:].isdigit():
                        pdata[namescape].setdefault(extra, extra_value)
    else:  # "dc+sd-jwt"
        for attr_group in (attributes_req, attributes_req2, issuer_claims):
            for attr in attr_group:
                if attr in data:
                    pdata["claims"][attr] = data[attr]
