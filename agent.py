#!/usr/bin/env python3
import angr
import claripy
import json
import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
if not DEEPSEEK_API_KEY:
    raise ValueError("请在 .env 文件中设置 DEEPSEEK_API_KEY")

client = OpenAI(
    api_key=DEEPSEEK_API_KEY,
    base_url="https://api.deepseek.com/v1",
)

class AngrTools:
    def __init__(self, binary_path="./crackme"):
        self.binary_path = binary_path
        self.project = angr.Project(binary_path, auto_load_libs=False)
        self.success_state = None
        self.sym_input = None

    def explore(self, **kwargs):
        self.sym_input = claripy.BVS("input", 8 * 10)
        state = self.project.factory.entry_state(stdin=self.sym_input)
        simgr = self.project.factory.simgr(state)

        def is_success(state):
            return b"Success!" in state.posix.dumps(1)

        def is_avoid(state):
            out = state.posix.dumps(1)
            return b"trapped" in out or b"Wrong password!" in out

        simgr.explore(find=is_success, avoid=is_avoid, num_find=1)

        avoid_len = len(simgr.avoid) if hasattr(simgr, 'avoid') else 0
        deadended_len = len(simgr.deadended) if hasattr(simgr, 'deadended') else 0
        active_len = len(simgr.active) if hasattr(simgr, 'active') else 0

        observation = {
            "found": len(simgr.found) > 0,
            "avoid_count": avoid_len,
            "deadended_count": deadended_len,
            "active_count": active_len,
        }
        if observation["found"]:
            self.success_state = simgr.found[0]
        return observation

    def solve_input(self, **kwargs):
        if not self.success_state or self.sym_input is None:
            return None
        state = self.success_state
        try:
            solution = state.solver.eval(self.sym_input, cast_to=bytes)
            password = solution.split(b'\x00')[0].decode('utf-8', errors='ignore')
            return password
        except Exception as e:
            print(f"求解异常: {e}")
            return None

class ReActAgent:
    def __init__(self, angr_tools):
        self.tools = angr_tools
        self.messages = [
            {"role": "system", "content": "你是一个二进制逆向分析专家。可用的工具有：explore（无参数）和 solve（无参数）。每次回答必须严格按以下格式：\nThought: 你的推理\nAction: explore 或 solve\nAction Input: {}\n不要输出任何其他内容，不要添加额外参数。"},
            {"role": "user", "content": "目标是找到正确密码，长度为4。存在陷阱死循环需要避开。请先调用 explore，然后我会给你观察结果，你必须再调用 explore 第二次进行确认，最后再调用 solve。至少进行三次工具调用。"}
        ]

    def call_deepseek(self, user_msg=None):
        if user_msg:
            self.messages.append({"role": "user", "content": user_msg})
        resp = client.chat.completions.create(
            model="deepseek-chat",
            messages=self.messages,
            temperature=0.0
        )
        reply = resp.choices[0].message.content
        self.messages.append({"role": "assistant", "content": reply})
        return reply

    def parse_action(self, text):
        lines = text.strip().split('\n')
        for line in lines:
            if line.startswith("Action:"):
                return line.split("Action:", 1)[1].strip().lower()
        return None

    def run(self, max_rounds=5):
        for round_num in range(max_rounds):
            print(f"\n=== 第 {round_num+1} 轮 ===")
            resp = self.call_deepseek()
            print(f"LLM 回复:\n{resp}\n")

            action = self.parse_action(resp)
            if not action:
                print("未识别到 Action，要求重试")
                self.messages.append({"role": "user", "content": "请按照格式输出 Action（explore 或 solve），Action Input 写 {}。"})
                continue

            print(f"执行 Action: {action}")
            if action == "explore":
                obs = self.tools.explore()
                obs_msg = (f"找到成功路径={obs['found']}, 避开陷阱={obs['avoid_count']}, "
                           f"死端={obs['deadended_count']}, 活动={obs['active_count']}")
                print(f"Observation: {obs_msg}")
                self.messages.append({"role": "user", "content": f"Observation: {obs_msg}"})
                # 强制要求再探索一次（除非已经执行过两次 explore）
                if round_num == 0:
                    self.messages.append({"role": "user", "content": "请再调用一次 explore 以二次确认路径。"})
                elif round_num == 1 and obs['found']:
                    self.messages.append({"role": "user", "content": "二次确认成功路径存在，现在请调用 solve 获取密码。"})
            elif action == "solve":
                pwd = self.tools.solve_input()
                if pwd:
                    print(f"Observation: 求解得到密码 = {pwd}")
                    print(f"\n🎉 最终密码: {pwd}")
                    os.system(f"echo '{pwd}' | ./crackme")
                    return pwd
                else:
                    print("Observation: 求解失败，无法提取密码。")
                    self.messages.append({"role": "user", "content": "求解失败，请再次调用 explore 并确认成功状态。"})
            else:
                print(f"未知 Action: {action}")
                self.messages.append({"role": "user", "content": f"错误：工具 '{action}' 不存在，只能使用 explore 或 solve。"})
        print("达到最大轮数，未获得密码。")
        return None

if __name__ == "__main__":
    tools = AngrTools("./crackme")
    agent = ReActAgent(tools)
    agent.run()
