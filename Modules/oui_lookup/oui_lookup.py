import re
import requests

OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
RE_SANITIZED_MAC_ADDRESS_LOOKUP_PATTERN = re.compile(r"^[0-9A-F]{6,12}$")
RE_NEW_MAC_ENTRY_PATTERN = re.compile(
    r"^(?P<OUI_OR_MAL>[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}) {3}\(hex\)\t{2}(?P<ORGANIZATION_NAME>.*)\r\n(?P<COMPANY_ID>[0-9A-Fa-f]{6}) {5}\(base 16\)\t{2}(?P<ORGANIZATION_NAME_BIS>.*)\r\n\t{4}(?P<ADDRESS_LINE_1>.*)\r\n\t{4}(?P<ADDRESS_LINE_2>.*)\r\n\t{4}(?P<ADDRESS_COUNTRY_ISO_CODE>.*)",
    re.M
)

class InvalidMacError(Exception):
    pass

class MacLookup():
    def __init__(self):
        self.oui_db = fetch_and_parse_oui_db()

    def lookup(self, mac_address: str):
        sanitized_mac = clean_mac_address(mac_address)
        if not RE_SANITIZED_MAC_ADDRESS_LOOKUP_PATTERN.search(sanitized_mac):
            raise InvalidMacError(
                f"Invalid MAC address: {mac_address}\n"
                 "Length should be between 7 and 11 of hexadecimal characters."
            )

        oui_or_mal = extract_first_three_pairs(mac_address)
        if oui_or_mal in self.oui_db:
            return self.oui_db[oui_or_mal]
        else:
            return None

def clean_mac_address(mac_address: str):
    """Remove any separators from the MAC address and convert to uppercase."""
    return mac_address.replace(":", "").replace("-", "").upper()

def format_mac_address(mac_address: str):
    """Format the MAC address as XX-XX-XX-XX-XX-XX"""
    cleaned_mac = clean_mac_address(mac_address)
    formatted_mac = "-".join([cleaned_mac[i:i+2] for i in range(0, len(cleaned_mac), 2)])
    return formatted_mac

def extract_first_three_pairs(mac_address: str):
    """Extract the first three pairs of characters from the MAC address."""
    cleaned_mac = clean_mac_address(mac_address)
    first_three_pairs = "-".join([cleaned_mac[i:i+2] for i in range(0, 6, 2)])
    return first_three_pairs

def fetch_and_parse_oui_db():
    def strip_tuple(tuple_to_strip: tuple):
        return tuple(map(str.strip, tuple_to_strip))

    response = requests.get(OUI_URL)

    oui_db: dict[str, list] = {}

    for match in map(strip_tuple, RE_NEW_MAC_ENTRY_PATTERN.findall(response.text)):
        oui_or_mal = match[0]
        organization_name = match[1]
        company_id = match[2]
        organization_name_bis = match[3]
        address_line_1 = match[4]
        address_line_2 = match[5]
        address_country_iso_code = match[6]

        if not oui_or_mal.replace("-", "") == company_id:
            raise ValueError(f"OUI/MA-L does not match company ID: {oui_or_mal} != {company_id}")

        if not organization_name == organization_name_bis:
            raise ValueError(f"Organization names do not match: {organization_name} != {organization_name_bis}")

        if oui_or_mal in oui_db:
            oui_db[oui_or_mal].append({
                "company_id": company_id,
                "organization_name": organization_name,
                "address_line_1": address_line_1,
                "address_line_2": address_line_2,
                "address_country_iso_cod": address_country_iso_code
            })
        else:
            oui_db[oui_or_mal] = [{
                "company_id": company_id,
                "organization_name": organization_name,
                "address_line_1": address_line_1,
                "address_line_2": address_line_2,
                "address_country_iso_cod": address_country_iso_code
            }]

    return oui_db