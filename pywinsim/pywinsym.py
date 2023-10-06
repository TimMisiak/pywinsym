import pdbparse
import pefile
import sys
import os
import shutil
import binascii

def get_pe_index(file_name):
    pe = pefile.PE(file_name)
    return f"{pe.FILE_HEADER.TimeDateStamp:X}{pe.OPTIONAL_HEADER.SizeOfImage:x}"

def get_pdb_index(file_name):
    p = pdbparse.parse(file_name, fast_load = True)
    pdb = p.streams[pdbparse.PDB_STREAM_PDB]
    pdb.load()
    guidstr = (u'%08x%04x%04x%s%x' % (pdb.GUID.Data1, pdb.GUID.Data2, pdb.GUID.Data3, binascii.hexlify(
        pdb.GUID.Data4).decode('ascii'), pdb.Age)).upper()
    return guidstr

if len(sys.argv) != 3:
    print("Usage: pywinsym.py <symbolStore> <file>")
    exit(1)

file_name = sys.argv[2]
store_path = sys.argv[1]

if file_name.lower().endswith(".exe"):
    index = get_pe_index(file_name)
elif file_name.lower().endswith(".pdb"):
    index = get_pdb_index(file_name)
else:
    print("Unsupported file type")
    exit(1)


base_name = os.path.basename(file_name)
dest_path = os.path.join(store_path, base_name, index)
os.makedirs(dest_path)
dest_file = os.path.join(dest_path, base_name)

shutil.copy(file_name, dest_file)

print(f"Successfully copied {base_name} to {dest_file}")