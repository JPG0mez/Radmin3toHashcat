import re
import click

@click.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.argument('output_file', type=click.Path(), required=False)
def main(input_file, output_file):
    """
    Quick script to convert Radmin Server 3 registry keys to hashes for Hashcat.
    """
    process_registry_file(input_file, output_file)

def parse_hex_string(hex_string):
    return bytes.fromhex(hex_string.replace(",", "").replace("\\", "").replace("\n", "").strip())

def parse_radmin_key(registry_data):
    # Extract the hex data after "=hex:"
    hex_data = re.search(r'=hex:(.*)', registry_data, re.DOTALL).group(1)
    key_data = parse_hex_string(hex_data)

    # Extract content from the binary data
    content = {}
    i = 0
    while i < len(key_data):
        dtyp = key_data[i+1] * 0x100 + key_data[i]
        dlen = key_data[i+2] * 0x100 + key_data[i+3]
        i += 4
        content[dtyp] = key_data[i:i+dlen]
        i += dlen

    username = content[16]
    salt = content[80]
    verifier = content[96]

    # Format for Hashcat
    hashcat_format = f"$radmin3${username.hex()}*{salt.hex()}*{verifier.hex()}"
    return hashcat_format

def process_registry_file(input_file, output_file=None):
    try:
        with open(input_file, 'r') as file:
            registry_data = file.read()
    except FileNotFoundError:
        print(f"Error: The file '{input_file}' was not found.")
        return
    except Exception as e:
        print(f"Error reading file '{input_file}': {e}")
        return

    # Split the content based on registry key header
    keys = re.split(r'\[HKEY_LOCAL_MACHINE\\', registry_data)
    
    output_lines = []
    for key in keys:
        if key.strip():
            # Add the part of the header
            full_key = "[HKEY_LOCAL_MACHINE\\" + key
            try:
                hashcat_format = parse_radmin_key(full_key)
                output_lines.append(hashcat_format)
                print(hashcat_format)
            except Exception as e:
                print(f"Error processing key: {e}")

    if output_file:
        try:
            with open(output_file, 'w') as file:
                for line in output_lines:
                    file.write(line + "\n")
        except Exception as e:
            print(f"Error writing to file '{output_file}': {e}")

if __name__ == '__main__':
    main()
