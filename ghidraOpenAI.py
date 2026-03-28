from openai import OpenAI
client = OpenAI()
code_snippet = """

void FUN_1402d9140(uint *param_1,byte *param_2,undefined8 param_3,undefined8 param_4)

{
  ulonglong uVar1;

  uVar1 = FUN_1402d8910(param_1,param_2,param_3,param_4);
  param_1[1] = (uint)uVar1;
  return;
}


"""

completion = client.chat.completions.create(model="gpt-4.1", messages=[{"role": "developer", "content": "You are a helpful assistant."}, {"role": "user", "content": "Hello!"}])
print(completion.choices[0].message)

