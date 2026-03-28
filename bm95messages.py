from ghidra.app.script import GhidraScript
from ghidra.program.model.util import CodeUnitIterator
from ghidra.program.model.symbol import SourceType
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.data import PointerDataType
from ghidra.program.model.symbol import SourceType

def create_bookmark(address, category, comment):
	bookmarkManager = currentProgram.getBookmarkManager()
	bookmarkManager.setBookmark(address, category, comment)

def main():
	messages_file_path = '/home/kth/Games/atomiciso/Atomic_Bomberman_ISO/messages.txt'
	messages_array_address = 0x00460250  # Replace with the actual address of g_msgtxtbuf0
	memory = currentProgram.getMemory()
	address = toAddr(messages_array_address)

	try:
		with open(messages_file_path.getPath(), 'r') as f:
			line_number = 0
			while True:
				line = f.readline()
				if not line:
					break
				line_number += 1
				line = line.strip()
				if not line or line.startswith('#'):
					continue

				parts = line.split(',', 1)
				if len(parts) == 2:
					message_id_str = parts[0].strip()
					message_text = parts[1].strip().strip('"')

					try:
						message_id = int(message_id_str)
						# Calculate the address of the pointer in the array
						pointer_address = address.add(message_id * 4) # Assuming 32-bit pointers

						# Get the pointer value from memory
						pointer_value = getInt(pointer_address)
						if pointer_value != 0:
							message_location = toAddr(pointer_value)
							create_bookmark(message_location, "Messages", f"ID: {message_id}, Text: \"{message_text}\"")

							# Optionally, create a data type at the pointer location
							string_data_type = currentProgram.getDataTypeManager().getDataType("/string")
							if string_data_type:
								createData(message_location, string_data_type)
							else:
								print("Warning: String data type not found.")
						else:
							print(f"Warning: Null pointer found for message ID {message_id}")

					except ValueError:
						print(f"Warning: Invalid message ID '{message_id_str}' on line {line_number}")
					except Exception as e:
						print(f"Error processing line {line_number}: {e}")
				else:
					print(f"Warning: Invalid format on line {line_number}: {line}")

	except Exception as e:
		print(f"Error reading messages.txt: {e}")

def xxxmain():
	messages_file_path = '/home/kth/Games/atomiciso/Atomic_Bomberman_ISO/messages.txt'

	messages_address = 0x00460250  # Replace with the actual address of the message buffer
	memory = currentProgram.getMemory()
	address = toAddr(messages_address)

	try:
		with open(messages_file_path.getPath(), 'r') as f:
			line_number = 0
			while True:
				line = f.readline()
				if not line:
					break
				line_number += 1
				line = line.strip()
				if not line or line.startswith('#'):  # Skip empty lines and comments
					continue

				parts = line.split(',', 1)
				if len(parts) == 2:
					message_id_str = parts[0].strip()
					message_text = parts[1].strip().strip('"')  # Remove surrounding quotes

					try:
						message_id = int(message_id_str)
						bookmark_comment = f"Message ID: {message_id}, Text: \"{message_text}\""
						create_bookmark(address, "Messages", bookmark_comment)

						# Move the address pointer forward. This is a guess!
						# You'll need to determine the actual size of each message entry.
						# If each message is just a null-terminated string, we can't know the size here.
						# If there's a structure involved, adjust accordingly.
						# This example assumes sequential storage of null-terminated strings.
						data_block = getDataAt(address)
						if data_block and data_block.isPointer():
							ptr_value = getAddressFactory().getAddress(str(data_block.getValue()))
							string_data = getDataAt(ptr_value)
							if string_data and string_data.isString():
								address = string_data.getMaxAddress().add(1) # Move past the null terminator
							else:
								print(f"Warning: Could not determine string length at {ptr_value} for line {line_number}")
								address = address.add(4) # Move by pointer size as a fallback
						else:
							print(f"Warning: Expected pointer at {address} for line {line_number}")
							address = address.add(4) # Move by pointer size as a fallback

					except ValueError:
						print(f"Warning: Invalid message ID '{message_id_str}' on line {line_number}")
				else:
					print(f"Warning: Invalid format on line {line_number}: {line}")

	except Exception as e:
		print(f"Error reading messages.txt: {e}")

class MessageLoaderScript(GhidraScript):
	def run(self):
		message_mapping = {}
		with open("messages.txt", "r", encoding="utf-8") as file:
			for line in file:
				parts = line.strip().split(',', 1)
				if len(parts) == 2:
					msg_id, msg_text = parts
					try:
						message_mapping[int(msg_id)] = msg_text
					except Exception as e:
						print(f"Error parsing line: {line.strip()}. Error: {e}")

		for addr in self.currentProgram().getMemory().getBlocks():
			symbol = self.getSymbolAt(addr.getStart())
			if symbol and "message" in symbol.getName().lower():
				msg_id = int(symbol.getName().split('_')[-1])
				if msg_id in message_mapping:
					print(f"Mapping Message ID {msg_id} → {message_mapping[msg_id]}")

		print("Message mapping complete.")




if __name__ == '__main__':
	main()

# [k.strip().split(',',1) for k in msgdata if k.strip().split(',',1) != [''] and len(k.strip().split(',',1))>1 ]
# maplist = [k.strip().split(',',1) for k in msgdata if k.strip().split(',',1) != [''] and len(k.strip().split(',',1))>1 ]
# maplist = [k.strip().split(',',1) for k in msgdata if k.strip().split(',',1) != [''] and len(k.strip().split(',',1))>=2 ]