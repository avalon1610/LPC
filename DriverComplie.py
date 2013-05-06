from subprocess import *
import re
from msvcrt import getch

class InteractiveCommand:
	def __init__(self,process,prompt):
		self.process = process
		self.prompt = prompt
		self.output = ""
		self.wait_for_prompt()

	def wait_for_prompt(self):
		while not self.prompt.search(self.output):
			c = self.process.stdout.read(1)
			if c == "":
				break
			self.output += c

		# clear the output buffer and return its content
		tmp = self.output
		self.output = ""
		return tmp

	def command(self,command):
		print command
		self.process.stdin.write(command + "\n")
		return self.wait_for_prompt()

# ########################################################
# setup driver environment variable here

# Winddk path
winddk = 'D:\\WinDDK\\7600.16385.1\\'

# [free=fre=f|checked=chk=CHK=c] [x86=IA32=I386|x64=x32-64|64=IA64] [WIN7|Wlh|WXP|WNET]
environment = 'chk'
platform = 'x86'
target_os = 'WIN7'

# build path,place them in order
build_path = ['E:\\Projects\\LPC\\LPC','E:\\Projects\\LPC\\LPCTest']
# ########################################################

set_env = ['%sbin\\setenv.bat' % winddk,winddk,environment,platform,target_os,'no_oacr']
command = ['cmd.exe','/k'] + set_env
print command

p = Popen(command,stdin=PIPE,stdout=PIPE)
prompt = re.compile(r"^[EeCcDdFfGg]:\\.*>",re.M)
cmd = InteractiveCommand(p,prompt)

for path in build_path:
	cmd.command("cd /d %s" % path)
	cmd.command("build")

cmd.command("exit")
getch()



	
