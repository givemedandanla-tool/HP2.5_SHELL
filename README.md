# HP2.5_SHELL — EXPERIMENTAL GOVERNANCE SPIKE

This public repository is currently used only by:

HP25-PUBLIC-PROTECTED-GOVERNANCE-SHELL-SPIKE-001

Purpose: test whether a public GitHub repository can serve as a mechanically protected approval / trust anchor for HP2.5 without publishing private source code.

## Important non-claims

- Scheme C has NOT passed merely because this repository exists.
- This is NOT the HP2.5 Runtime, Control Plane, Wake-Up Plane, or production shell.
- ROOT-F-001 is NOT closed by this repository's existence.
- Approval records are meaningful only after server-side protection and gate behavior are mechanically verified.

## Public-data rule

This repository must contain governance metadata and synthetic spike fixtures only. Do not publish private source code, private patches, prompts, user content, credentials, tokens, cookies, passwords, or secrets.

## Trust model under test

A protected canonical approval record may point to an exact immutable source repository identity + 40-character commit SHA. A newer engineering HEAD does not automatically become approved.

## 正式採用 policy 候選的範圍

這份修訂提供尚未安裝的正式治理模式採用入口。發布候選分支、通過本地測試或
取得獨立預審，都不會改變受保護 main 的 policy 或 state，也不代表正式採用、
任何精確版本批准、main merge 或 production 啟用。

`evaluate_rotation()` 保持原本 mode 不可變的規則。新增的
`evaluate_formal_adoption()` 只接受 `EXPERIMENTAL_SPIKE` 到 `FORMAL_SCHEME_C`
的單向變更，要求 generation 精確加一、新的一次性 generation-bound 有限
Human-parented Authority、不同 Writer／獨立 Auditor 及 receipt SHA-256。
其餘 policy、schema、已批准 revision、last approval ID 與額外欄位都保持
原有拒絕規則。正式採用只能使用以下精確固定的 note：

```text
正式 Scheme C 治理模式；精確版本批准與 production 啟用須另行授權。
```

`evaluate_state_change()` 只依 mode 變更選擇正式入口，note 不能啟動該入口。
缺失或未知 mode、正式模式降級、重複正式採用、跳代、過期 Authority、重播
Authority 或自我稽核會被拒絕。正式模式下維持 mode 的有限 Authority 輪替
仍是一般 rotation；它不表示再次採用或批准新版本。

CLI 沿用同一個 state-only gate entrypoint，從受保護 base 執行。無論一般
輪替或正式採用，仍必須查驗 GitHub 最新 Owner `APPROVED` review 綁定 PR
目前 exact 40 字元 head，且 Owner 必須與 PR author 不同。過期 SHA、被
dismiss 的 review、其他 reviewer 或 Owner 自評都不成立。候選 workflow
和程式不會因此成為受信任執行來源。

## 安裝前操作與目前阻斷

1. 重新讀取受保護 main 的 exact SHA、state、workflow、Ruleset、required
   check 與目前 Authority／Lease；歷史過期授權不能重播。
2. 固定候選 full SHA、相對 trusted base 的完整 diff、實際測試結果和獨立
   預審範圍。候選 state 仍維持 `EXPERIMENTAL_SPIKE`，不附正式 manifest。
3. 目前 incumbent gate 只接受單檔 `approval/manifest.json` 或
   `governance/state.json`；一般 rotation 又保持 mode 不變。因此現有
   no-bypass policy **沒有合法的 policy 安裝或正式 mode 切換通路**。
   此候選不能自行放寬舊 trusted gate，也不能將 candidate self-test、
   skipped job 或錯 SHA 的結果當成 required protected gate PASS。
4. 在沒有另行授權、獨立預審的合法安裝機制以前，停在
   `PREPARED_NOT_INSTALLED / BLOCKED_TRUSTED_POLICY_INSTALL_PATH`。
   不更動 Ruleset、不加 bypass actor、不停用 required check、不硬 merge。
5. 若日後 Human 選定合法安裝機制，先重新核對 exact policy candidate、
   機制與權限及 current trusted base。policy 安裝完成後仍須以新的有限
   Authority／Lease 和另行 Human 決策準備 state-only 正式採用 PR，完成
   distinct Owner exact-head review 與 genuine protected gate 驗證。
6. 正式治理模式接受、精確版本 manifest 接受、工程 main merge 和
   production 啟用各自需要適用的授權與驗證；不得互相推導。

## 來源證據與公開資料限制

固定 note 或 SHA-256 摘要不是 authenticated attestation。現有 gate 檢查
資料格式與 envelope 綁定，不會自動認證私有 CI／audit 的來源。Owner 最終
exact-head review 必須獨立核對來源 repository ID、完整 repository name、
exact source SHA、同 SHA 的 CI，以及獨立 Auditor 的原始 receipt 和摘要。
Writer 提供的 JSON claim 不能替代這些來源核對。

在沒有已驗證且隔離的自動 provenance 通路時，不得宣稱具備自動來源認證或
production readiness。若正式採用契約所需的不可偽造證據仍缺失，保持
BLOCKED；任何 credential、signer 或 App 的安裝／擴權都須另行授權與預審。
此公開 repository 只保存最少治理 metadata、opaque evidence ID／摘要和
synthetic fixtures；不要發布私有來源、patch、prompt、Human grant 或 user
content，更不可發布 credentials／secrets。

## 中止與回復

候選、main 或 evidence 改變後，重新固定 exact SHA 和 fresh review；不可
延長到期 Authority、續用 stale Lease 或把舊 review 借給新 commit。遇到
缺失授權、未知來源、安裝阻斷或測試失敗時，停止新的正式採用／manifest，
保存 exact evidence、解除自己持有的 Lease，記錄 blocker 與下一個合法 actor。

保留 Shell 歷史與既有精確批准；不要 force-push、刪除 Shell、重寫批准或
更改 Ruleset。工程 HEAD 移動不會改變已批准 revision。正式採用入口只允許
單向 lifecycle，沒有自動降級／回滾 mode 的通路；後續撤銷或替代 policy
必須經另行明確 Human 決策、獨立預審與合法受保護機制。
