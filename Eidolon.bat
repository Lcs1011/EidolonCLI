@echo off


set ANTHROPIC_API_KEY=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



"C:\EidolonCLI\claw-code\rust\target\release\claw.exe" --model anthropic/claude-haiku-4-5 --permission-mode review-write %*