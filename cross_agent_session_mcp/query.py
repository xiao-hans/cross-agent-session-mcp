r"""调用方传入标准记录的有界过滤与逐来源覆盖汇总（DES-API-01「查询合约」、DES-DATA-01）。

服务的需求条目：SRS-SEARCH-01（关键词/时间/项目/来源组合过滤与有界结果）、SRS-SEARCH-02
（逐来源状态与截断）、SRS-SEARCH-05（只用记录内带时区时间解释范围，无时间不猜）、
SRS-SEARCH-09（坏行、提前中止、资源触限不得冒充「完整且无匹配」）。

本层的输入是**调用方已经拿到的** `models.StandardRecord` 序列：不做文件发现、不打开任何
文件、不解压、不 import 协议层，也不接 `server.py`。它只回答两个问题：这批记录里哪些通过
过滤（按来源有界返回），以及每个来源的覆盖状态该说什么。

本层是纯过滤，不是发布许可
------------

- **调用方标志不构成授权**：本函数不接受 `scope`，也不看任何「已授权」「可发布」式布尔值。
  授权判定属于 `policy.py`（存储授权 + 归属核对两次独立调用）；本层被调用不代表调用方有权
  拿到这些记录，本层返回的元数据也不表示某条记录已获得发布资格。尤其：**本层返回的映射项目名
  不是授权结论**，也不是来源绑定结论（见下条）。
- **不做整流身份核对**：会话身份与项目归属的一致性核对在 `session_stage.py`，本层不重做也
  不替代；本层只看记录自带的 `time_quality`/`project_quality` 与 `location`。
- **不做遮蔽**：输出因此**不含任何正文与片段**（DES-SEC-01「输出有界」在本层的落点）。返回
  的是「第几条记录命中」的序号与记录自带的短元数据；正文留在调用方手里，等 `redaction.py`
  与授权层接线后由后续协调层决定给不给、给多少。正因为不给正文，本层也不需要片段长度上限。
- **项目映射只是输入契约，不是授权，也不是来源绑定**：`project_mappings` 由协调层显式给出
  「记录序号 → 已映射项目名」，本层只按这个映射做收窄与回填。命中即返回映射名**不**表示该记录
  已获授权，也**不**表示它的来源身份已被核对——归属核对（`policy.authorize_attribution`）证明的
  是「路径 → 项目」的一次映射，记录的来源绑定另需来源可信字段、会话身份核对与整流一致性
  （DES-API-01 发布边界、DES-SEC-01）。协调层未完成这两件事时，本层的结果仍不得发布。
- **诚实覆盖与流级不完整**：坏行、非对象行、形状不可解释等**已产出记录**的问题随
  `record.issues` 带过来，本层能逐码计数并使来源 `partial`；而「未产出记录」的那类（坏行、解压
  失败、行数触限后未读的部分）本层看不见，唯一登记通道是 `scan_filter(..., stream_partial=True)`。
  它为真时每个来源都记 `parse_incomplete` 且 `partial` 为真（只会收紧）；省略该参数只说明
  调用方未申报，**不构成本层对完整性的证明**，也不得被上层当成「已核实完整」的依据。
- 因此「命中 0 条」在本层不等于「可以发布 0 段正文」，也不等于「该来源没有相关内容」：
  覆盖信息里的 `partial` 与 `filter_errors` 才是判据。

过滤判据
------------

- **关键词**：对记录正文与两侧都做**同一个** `str.casefold()`，再做子串匹配（SRS-SEARCH-05
  要求支持中文：`casefold` 对汉字是恒等变换，因此中文匹配就是原文子串匹配）。不做变音/全半角
  归一、不做分词、不做语义匹配，也不使用任何正则（不受控文本进正则引擎会把工作量交给数据侧）。
  关键词整体匹配一次，不按空白拆词：拆词等于给调用方一个未声明的 OR 语义。
- **时间**：带 `query` 时允许只给一端（另一端开放），但给出的那一端**必须带时区**；省略 `query`
  时 `start`/`end` 必须**同时**给出（只靠时间收窄的查询不给两端就是无界时间扫描）。任一端无时区、
  不可解析或类型不合都是参数错误，不回填本地时区。区间**左闭右开**：`start <= t < end`；
  `start == end` 是合法的**空区间**（不报错，返回 0 命中）。单边区间同样左闭右开：只有 `start` 即
  `[start, +∞)`，只有 `end` 即 `(-∞, end)`。只有 `time_quality is EXACT` 的记录参与时间比较；
  无时间/无时区/时间不可解析的记录**不猜**（不拿文件 mtime、不拿头部时间、不回填时区），
  有区间条件时被排除；这类缺口计 `time_unusable`（无论本次是否带时间条件，只要记录自报了时间
  问题就记），使该来源 `partial` 为真。边界值**只**接受带时区的 `datetime` 或 ISO 8601 字符串
  （字符串统一走 `models.normalize_timestamp`，含字符串长度上限）；**纪元数字与 `bool` 不是合法
  边界**：`normalize_timestamp` 会按量级猜秒/毫秒/微秒，而一个裸数字无法证明调用方想要哪种单位，
  因此在 `_bound` 入口就判不可用（固定拒绝码），不交给它猜。无时区字符串在这里同样是拒绝，
  不是「按本地时区解释」。过滤界与记录时刻**统一规范化到 UTC** 后才比较与外出：记录自报 `EXACT`
  却因 `astimezone` 越界（极端年份）拿不出时刻时，固定降级为「时间不可解释」（引用里
  `timestamp=null`、质量降为 `INVALID`，来源记 `time_unusable` 并 `partial`）——既不让整次查询抛异常，
  也不把越界的原值外出。
- **项目**：判据是**映射表**，不是记录自带的 `project`。根因：`StandardRecord.project` 是
  **cwd**（来源侧字段），请求的 `project` 是**策略项目名**（`ProjectGrant.name`），两者不是同一种
  值，直接做 `casefold` 相等比较永远判不出真实归属。因此本层要求协调层显式提供
  `project_mappings: {记录序号: 已映射项目名}`：
  **不论是否点名 `project`**，没有映射的记录一律排除并使来源 `partial`（也不论其
  `project_quality` 是什么、是否 `sourced`——`quality.sourced` 只说明「值有出处」，
  不说明「已映射到策略项目名」）：缺映射是「判不出归属」，既不能算命中，也不能当成
  「不属于任何项目」而静排除；不点名时本层也不拿它冒充一属主（DES-API-01：结果
  不包括无法确认项目归属的记录）。点名 `project` 时再拿映射名做**精确匹配**比较（`==`，不
  `casefold`、不做路径规范化、不做前缀匹配）——项目名是策略配置里的标识符，折叠大小写等于替
  配置发明一条它没有声明过的等价关系，还会让两个只差大小写的已批准项目互相命中。不点名项目时，
  返回引用中的项目名同样使用映射名（未映射为 `None`），以免把 cwd 当作项目对外出示。映射表本身
  受有界性约束（见「有界性与资源上限」），键必须是本批内的整数序号，值必须是非空白、
  ≤ `MAX_PROJECT_VALUE_CHARS` 的 `str`。
- **来源白名单**：`sources` 只接受六个精确来源 ID（`SUPPORTED_SOURCES`：hermes、dsh、workbuddy、
  pi、cursor_agent_cli、codex）。`unknown` 是**内部桶名**，不是可请求的来源：点名它或任何集合外的
  值都是参数错误（`filters_sources_invalid`），因为「查 unknown 来源」没有合法语义，把它当普通分组
  放行等于给调用方一个绕过来源白名单的口子。记录自带的来源 ID 不在六个之内时仍归入内部
  `unknown` 桶。该桶是**诊断桶，不是可匹配集**：无论 `sources` 是否点名，整桶都不做逐条判定、
  不动两道字符预算、不占返回额度，`records_scanned=matched_count=returned_count=0`，传入记录**全部**
  计入 `skipped_count`；整桶只登记一次 `unknown_source` 并使该桶 `partial`（`status=incomplete`）。
  不拿它冒充六类来源中的任何一类，也不让一条来源不可识别的记录外出成结果。
- **点名来源必须有交代**：`coverage` 的行覆盖**所有点名来源**（先按 `SUPPORTED_SOURCES` 的固定顺序），
  不再只覆盖「本批恰好有记录」的那些。点名但本批没有记录（或其记录全在 `unknown` 桶）的来源记为
  「**未扫描**」：`records_scanned=0`、`matched_count=0`、`partial=True`、错误码 `source_not_scanned`，
  状态 `incomplete`。这不是「搜而无匹配」——本层看不见未产出的记录，把缺源写成 `no_match` 就是
  伪造「该来源没有相关内容」（SRS-SEARCH-09）。传入记录落入的、未点名的内部桶同样如实成行
  （`unknown_source` + `partial`），不静默丢弃。
- **参数校验只做一次**（入口）：`records` 必须是字面 `list`/`tuple`（生成器等一次性可迭代
  对象不能预先计数，直接拒绝——所有上限都必须在消费之前生效）；每条元素必须是
  `StandardRecord` **且字段形状可预期**（`text` 为 `str`、两个质量字段为本包枚举、`location` 为
  `SourceLocation`、`issues` 为元素均为 `IssueCode` 的字面 `tuple`）——形状不合整批拒绝，
  不逐条丢弃：`issues` 里混进数据侧字符串会把不受控的值写进对外计数；`query` 必须是非空白、
  长度 ≤ `MAX_KEYWORD_CHARS` 的 `str` 或 `None`；`project` 同形态（长度上限与解析侧的项目值口径
  一致，见 `MAX_PROJECT_VALUE_CHARS`）；`project_mappings` 为 `None` 或普通 `dict`（`Mapping` 不收：
  它的 `__getitem__` 可以被任意实现，本层要按整表校验长度并在消费前判窗口），键为落在本批范围内的
  整数序号（`bool` 不算），值为非空白、≤ `MAX_PROJECT_VALUE_CHARS` 的 `str`，条目数 ≤
  `MAX_RECORD_MAPPINGS`；`sources` 必须是 ≤ `MAX_SOURCES_PER_QUERY` 项的 `list`/`tuple`，元素为
  `SUPPORTED_SOURCES` 中的精确 ID（不做大小写折叠，`unknown` 不可请求）；`limit` 为 1–100（与协议层
  `search_sessions` 同一口径，`bool` 不算整数）；`max_records`/`max_scan_chars`/`max_total_scan_chars`
  为 `None` 或正整数（超硬限按硬限钳制）。任一项不合 → `rejected=True`，**不消费任何记录**，
  不返回部分结果。

有界性与资源上限
------------

四层独立的界，缺一不可，方向都是「装不下就明说」而不是「少吃一点假装看完了」：

1. `max_records`（默认 `MAX_FILTERED_RECORDS`，硬钳 `MAX_FILTERED_RECORDS_HARD_LIMIT`）：
   **进入过滤的记录条数**。超出即在消费前拒绝（`record_set_too_broad`）。这一层存在的理由：
   扫描字符预算只约束工作量，不约束本层自己留下的那层「已匹配待返回」的下标列表；
   它封住的是本层的额外驻留（只持引用，不复制记录）。（调用方列表本身归调用方内存范围。）
2. `max_scan_chars`（默认 `MAX_SCAN_CHARS`，硬钳 `MAX_SCAN_CHARS_HARD_LIMIT`）：**每个受支持来源**的扫描
   字符预算（只计 `record.text`，见「计量的对象」；内部 `unknown` 诊断桶不扣它）。触限即停止扫描该来源剩余记录，该来源标
   `partial`、错误码 `scan_resource_limit`；因分组按记录序号升序遍历，**该来源后面的记录**就是未扫描
   的部分，`skipped_count` 因此是逐源如实的计数。
3. `max_total_scan_chars`（默认 `MAX_TOTAL_SCAN_CHARS`，硬钳 `MAX_TOTAL_SCAN_CHARS_HARD_LIMIT`）：
   **全查询**的字符预算，与逐源预算**共限**（两道都在生效，不是二选一）。它封住的是
   「每源预算 × 来源数」拉动的总量。触限即停止扫描（含当条之后的一切记录），且 `global_hit`
   是**不可恢复状态**：一旦置位，后续每个桶在**逐条预算比较之前**先守住它，一条也不再扫——
   只比额度拦不住正文为空的记录（`0 > global_left` 判假），那会让「已用尽」和「还在扫」同时成立。
   顶层 `global_scan_limit_hit` 为真、`skipped_records` 给出未扫描条数、`complete` 为假。**逐源仍然如实**：
   被本预算打断或拦在门外的桶记自己的 `global_scan_limit` 码并使该行 `partial`（不顶替该源自家的
   `scan_resource_limit`，两道预算是不同的限），已扫到一半的来源也不会因为「只是全查询用尽」
   就被报成完整无匹配；一条也未扫到的桶另记 `source_not_scanned`。
4. `limit`：**全查询返回的总条数**（不再是每来源）。按固定来源顺序（`SUPPORTED_SOURCES` 优先，
   内部 `unknown` 桶最后）逐源消耗同一份额度，额度用尽即后面的来源一条也不返回（`unknown` 桶
   不参与：它不占额度也不被额度影响）。截断是
   **逐源如实**的：有匹配未全部返回的来源记 `result_truncated`、`partial` 为真，`matched_count` 仍是
   该来源**已扫描记录中**的全部匹配数（不是返回数），`returned_count` 是实际给数。稳定顺序：返回按
   `(来源分组, 记录序号)` 升序，不随来源命中多少重排。
   **本层不保留全部命中列表**：返回额度是全查询共享的（`limit` 递减），一个来源最多只能占走剩余额度，
   多余的匹配只计入 `matched_count` 不保留引用，所以返回总数永远 ≤ `limit`，
   额外驻留也不随匹配数增长。

`matched_count`、`total_matched` 与 `skipped_records` 用无上限整数：若给它们也加封顶，封顶值本身就成了第二个
「匹配数」，被当计数使用时谎报规模——计数不设上限，**被保留的对象**才设上限。

`max_records` 与 `MAX_RECORD_MAPPINGS` 是**记录数**上限，不是字符工作量上限：一条记录可以携带
接近 `MAX_SCAN_CHARS` 的正文，因此「条数封顶」不能冒充「工作量封顶」，文档与对外描述不得把
记录数上限说成字符预算。字符工作量只由 `max_scan_chars`（逐源）与 `max_total_scan_chars`（全查询）
两道预算共同封顶。

计量的对象：只计每条记录的 `text` 字符数。关键词已在入口封顶长度且全查询只归一化一次；
会话标识、角色、执行者与位置标签都是短字符串（本层按 `MAX_*_CHARS` 判形后使用），
按条数而非字节计量已经足够；正文是唯一长度由来源决定的字段。归一化与比较只在**通过预算的**
记录上执行，预算耗尽之后不再折叠任何文本，因此预算确实封顶了工作量，而不是只封顶结果大小。

每来源的过滤期错误是一个**去重集合**，元素取自闭合枚举 `FilterErrorCode`，因此它的长度天然
受枚举成员数约束：不需要另设条数上限，也不存在由数据侧或来源数拉动的无界诊断。

返回值的形状
------------

- `ScanFilterOutcome.rejected` / `.reason`：入口校验结论。拒绝时不扫描、不返回任何记录信息，
  也**不回显任何调用方输入**（错误码是闭合枚举，固定文案表提供说明）。
- 零分组（传入空列表，且未点名任何来源）时 `coverage` 为空元组：本层不伪造「该来源已搜而无
  匹配」，并且 `complete` 直接为假——**一行覆盖都没有时，「完整」就是未证明的说法**，调用方不必
  自己拿 `coverage` 是否为空反推。只要点名了来源，`coverage` 就必有同数行（未扫到的行以
  `source_not_scanned` 明示，见上节），不再出现「点名了六个源但只拿到两行」的隐性缺口。
- `matches`：`MatchRef` 元组，按 `(来源分组, 记录序号)` 稳定升序，跨来源**不分池**、不重排。
  序号 `record_index` 是输入序列中的 0 起始下标，跨来源唯一，因此调用方可以用它回到自己那份
  列表取正文，也是 `project_mappings` 的键；`sequence` 是本层给出的来源内稳定排序**名次**（按
  `(行号, 同行产出序号)` 排序后的位置，不是行号本身，值域≤该来源返回条数）；任一位置不可解释则
  整来源为 `null`。
- 每条 `MatchRef` 只带**固定字段**：来源、会话标识、角色、执行者、规范化 UTC ISO 8601 时间、
  时间质量、**映射项目名**、项目质量、位置引用串与两个序号。正文、关键词命中位置、命中次数一概不返回。
  `MatchRef.project` 是 `project_mappings` 给出的策略项目名（无映射为 `null`），**不是**记录自带的
  `record.project`（那是 cwd）；cwd 从本层外出就等于把一个未映射的路径冒充项目标识。
  短元数据在返回前做**形态判定**：会话标识/角色/执行者**带着值但形状不合**时，除降为 `null` 外还按
  来源记 `record_field_out_of_bounds`（本层拿不出这个字段就是覆盖缺口，不能只在值里留个 `null`）；
  参预项目判定的映射缺失记 `project_unattributed` 并使来源 `partial`。
  位置不可解释则引用串不外出，并按来源记 `location_unreadable`。本层只剥返回值的首尾空白，
  不按长度截断、不做归一，也不把形状不合的值原样外出。
- `coverage`：逐来源 `SourceCoverage`，含 `matched_count`、`returned_count`、
  `records_scanned`、`skipped_count`（本层未看到的该源传入记录数）、`scan_chars`、`filter_errors`、
  `quality_issues`（逐码计数 `issue_code=count`，**只计会使覆盖不完整的那些原因码**）、`partial`
  与 `reason`（一句人话，只由固定片段拼成，不含原值）。
  `status`：有返回 → `searched`；零返回且 `partial` → `incomplete`；零返回且完整 →
  `no_match`。只有第三种情况可称「无匹配」（SRS-SEARCH-09）：`partial` 由**本行错误码非空**推得，
  而点名未扫描、逐源预算触限、缺项目映射、流级申报都会使其非空，所以上面那句「零返回且完整」
  在本层只对「确实扫完且无错」的来源成立。两个码的分工是固定的：`source_not_scanned` 是**通用未扫描**
  判据（点名却无记录、或被任一字符预算拦在门外都记它），`result_truncated` **只由全查询返回总上限**
  产生——扫描提前中止不记它，未扫的部分由 `skipped_count` 与预算码承担。内部 `unknown` 诊断桶
  只记 `unknown_source`（它的缺口是来源不可识别，不是未扫描也不是截断）。顶层另有
  `unscanned_sources`/`global_scan_limit_hit`/`skipped_records`：全查询级的缺口不塞给某一个来源，
  但必须能从返回值上看到。
- 覆盖结论的保守方向：**只会把 `partial` 判为真，绝不反向收紧**。一条记录同时带来多个后果时
  （未知来源 + 无时间 + 归属不明），几个错误码同时登记；反之，任何一次触限都不会因为
  「后面的记录大概也不匹配」而被省略。
- `as_public_dict()` 只含整数、布尔、固定枚举与本模块自有键，不含正文、路径与任何原值片段，
  可直接进日志与对外覆盖信息（与 `ParseStats.as_public_dict()` 同一约束）。

与解析侧统计口径的关系
------------

`ParseStats.partial` 回答的是「整流字节是否都读懂」；`SourceCoverage.partial` 回答的是
「本次过滤对该来源的结论是否完整」。本层对二者的处理：**凡随记录带过来的解析侧原因码**（元素
不在 `models.NON_PARTIAL_ISSUES` 里）既计入 `quality_issues`，也使本来源 `partial` 为真——它们
同源于 `IssueCode` 闭合枚举，不拿数据侧字符串当键。不降级覆盖的只有三类：空行、本身无文本、
已识别的非检索正文块（与解析侧完全同口径，本层不另列名单）。但两者仍不互推：解析完整但无时区
的记录会让查询侧不完整；而解析侧「行未读出记录」的那部分（坏行本身不产出 `StandardRecord`，
本层根本看不到）只能靠 `stream_partial` 申报。把两侧合并映射到对外 `coverage.status` 字符串
（`disabled`/`unavailable`/`unsupported`/`error`）仍属后续协调层。

本增量状态（不得理解为功能已完成）
------------

- 已实现：入口一次性参数校验与固定拒绝码、关键词 `casefold` 子串匹配、左闭右开带时区时间
  区间过滤（有 `query` 时允许单边，无 `query` 时双端必填；边界只收 `datetime`/ISO 字符串且统一到
  UTC）、**基于协调层映射表的项目收窄**（序号→策略项目名，精确匹配，缺映射即排除并标不完整）、
  六个精确来源 ID 白名单与**整桶不产结果的内部 `unknown` 诊断桶**、逐源与全查询两道字符预算
  （`global_hit` 为不可恢复状态）、**全查询总返回上限与逐源如实截断计数**、点名来源的「未扫描」行、
  `stream_partial` 申报通道、逐来源覆盖汇总与 `status`/`partial`/`reason`、`as_public_dict()`。
- 接线现状：`scan_filter` 已由 `file_search.py` 作为单批内部过滤入口调用（预检拒绝与命中过滤
  都走本层）；授权（`policy.py`）、整流核对（`session_stage.py`）、遮蔽与片段输出
  （`redaction.py`/`publication.py`）、`coverage.status` 映射由那个协调层自己完成，本层仍不
  参与它们，也不接 `server.py`、不做文件发现/打开/解压、不做分页游标。
  `scan_filter` 始终是**给协调层用的内部入口**。
- 协调层仍需自行完成（本层不代替，也不因本层返回而得出不成立的结论）：把 `authorize_attribution`
  的项目级归属根与记录 cwd 接上、从已映射项目名回到 `authorize_query(scope, project=...)` 的合法性
  校验（本层不查策略配置）、**来源绑定与会话身份核对**、逐源发现与未产出记录的上报、把本层的
  `incomplete`/`source_not_scanned` 映射为对外 `coverage.status`、以及与发布门相关的任何布尔值。
- 未验证：本轮不运行任何代码与测试，全部判据只经过静态推导，待审查与测试复核。
- 运行前提：Python 3.11+（`StrEnum`、`datetime.UTC`）。不新增依赖。

依赖限制（DES-ARCH-02）：只用标准库与本包 `models`；不导入 `mcp`、`server.py`、`policy.py`、
`session_stage.py`、`redaction.py` 或任何来源适配器；不打开文件、不读配置与环境变量、不写日志、
不建索引、不持久化。本层无状态：同样的输入永远得到同样的输出。
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .models import (
    NON_PARTIAL_ISSUES,
    TIMESTAMP_ISSUES,
    IssueCode,
    ProjectQuality,
    SourceLocation,
    StandardRecord,
    TimeQuality,
    normalize_timestamp,
)

__all__ = [
    "DEFAULT_LIMIT",
    "FilterErrorCode",
    "FilterWindow",
    "MAX_CALLER_KEY_CHARS",
    "MAX_FILTERED_RECORDS",
    "MAX_FILTERED_RECORDS_HARD_LIMIT",
    "MAX_KEYWORD_CHARS",
    "MAX_LINE_NO",
    "MAX_MATCH_ORDINAL",
    "MAX_PROJECT_VALUE_CHARS",
    "MAX_RECORD_MAPPINGS",
    "MAX_SCAN_CHARS",
    "MAX_SCAN_CHARS_HARD_LIMIT",
    "MAX_SESSION_ID_CHARS",
    "MAX_SOURCE_ID_CHARS",
    "MAX_SOURCES_PER_QUERY",
    "MAX_TOTAL_SCAN_CHARS",
    "MAX_TOTAL_SCAN_CHARS_HARD_LIMIT",
    "MatchRef",
    "QueryRejectionReason",
    "REJECTION_MESSAGES",
    "SUPPORTED_SOURCES",
    "ScanFilterOutcome",
    "SourceCoverage",
    "SourceFilter",
    "CoverageStatus",
    "scan_filter",
]

#: 六个可查询来源的**精确 ID**，固定顺序（也是 `coverage` 与全查询截断的遍历顺序）：
#: 与 `policy`/`server.REQUIRED_SOURCES` 同一组 ID。本层不导入策略层（DES-ARCH-02
#: 「范围保护」），两处需同步维护；这里只用于**白名单与分组**，不用于授权。
SUPPORTED_SOURCES: tuple[str, ...] = (
    "hermes",
    "dsh",
    "workbuddy",
    "pi",
    "cursor_agent_cli",
    "codex",
)
_KNOWN_SOURCE_KEYS: frozenset[str] = frozenset(SUPPORTED_SOURCES)
#: 未知来源 ID 的**内部**分组键：不是可请求的来源 ID（入口拒绝点名它），也不冒充六类来源。
_UNKNOWN_SOURCE_KEY = "unknown"

#: 关键词长度上限：与协议层 `search_sessions.query` 同为短文本；`MAX_CALLER_KEY_CHARS` 是
#: 其它调用方短标识的统一上限，关键词单独放宽到 512（整句检索是正常用法）。
MAX_KEYWORD_CHARS = 512
#: 调用方短标识（来源 ID、角色、执行者）的统一形态上限。
MAX_CALLER_KEY_CHARS = 128
#: 来源 ID 的形态上限：六个合法 ID 最长 16 字符，64 已留出余量。作用是在集合成员判定（要哈希
#: 整串）**之前**先把长度挡住，避免为一条携带超长 `source` 的记录或参数去哈希一个任意长的串。
#: 超长值既不是可请求的来源（入口拒），也不会落进受支持分组（解析侧归 `unknown` 桶）。
MAX_SOURCE_ID_CHARS = 64
#: 项目值的长度上限（调用方收窄值与 `project_mappings` 的值共用）：与解析侧
#: `sources/pi.MAX_PROJECT_VALUE_CHARS`（512）同口径——它卡的是「一个可外出的短标识」而不是
#: 仓库路径形态，拿 128 判形会把策略侧认为合法的项目名降为 `null`，并在收窄时误报不完整。
MAX_PROJECT_VALUE_CHARS = 512
#: 会话标识的**返回**上限：与解析侧 `sources/pi.MAX_SESSION_ID_CHARS`（256）同口径。超长的会话标识
#: 在本层不是错误，只是不外出（降为 `null`）——它已经进了调用方的列表，本层没有义务再传一次。
MAX_SESSION_ID_CHARS = 256
#: 位置行号的合法范围与同一行内产出记录序号的上限（`SourceLocation` 的取值形态约定）。
#: 名次由这两个字段排序后的**位置**得出，因此名次值域≤ 该来源实际返回条数（≤ `LIMIT_MAX`），
#: 无需另设上限。
MAX_LINE_NO = 10**12
MAX_MATCH_ORDINAL = 65_535
#: 点名来源的条数上限：六个受支持来源再加一点余量就不像一次查询的参数了。
MAX_SOURCES_PER_QUERY = 32

#: 返回**总**条数默认值与允许范围（与协议层 `search_sessions` 的 `limit` 同一口径）。
#: 注意语义：`limit` 是全查询总上限，不是每来源上限。
DEFAULT_LIMIT = 20
LIMIT_MIN = 1
LIMIT_MAX = 100
#: 进入过滤的记录条数窗口：默认 10 万条，可下调，硬钳 100 万条。**这是记录数上限，
#: 不是字符工作量上限**，不得在对外描述中当作后者（见模块文档「有界性与资源上限」）。
MAX_FILTERED_RECORDS = 100_000
MAX_FILTERED_RECORDS_HARD_LIMIT = 1_000_000
#: 每来源扫描字符预算：默认 8 MiB 字符数，硬钳 64 MiB。总量随来源数增长，
#: 因此另有 `MAX_TOTAL_SCAN_CHARS` 封全查询。
MAX_SCAN_CHARS = 8_388_608
MAX_SCAN_CHARS_HARD_LIMIT = 67_108_864
#: 全查询扫描字符预算（与逐源预算**共限**）：默认 32 MiB，硬钳 128 MiB。
#: 逐源预算封顶单源工作量，本预算封顶「六源 × 逐源预算」拉动的总量。
MAX_TOTAL_SCAN_CHARS = 33_554_432
MAX_TOTAL_SCAN_CHARS_HARD_LIMIT = 134_217_728
#: 一条查询可接受的「记录序号 → 项目名」映射条目数上限：硬钳到记录窗口默认值（10 万）。
#: 本层不拿映射表猜未提供的对应关系，但必须预先判住这张表本身不成为无界输入。
MAX_RECORD_MAPPINGS = 100_000


class CoverageStatus(StrEnum):
    """本层可自证的逐来源覆盖状态（DES-API-01 状态的**下界**，见模块文档）。

    本层只扫描调用方传入的记录，因此只能产出三种结论；`disabled`/`unavailable`/
    `unsupported`/`error` 描述的是来源本身，属于尚未实现的协调层与发现层。

    `INCOMPLETE` 同时覆盖两种失效：该源扫了但不完整，以及**点名该源但本批一条记录也没扫到**
    （后者另由 `source_not_scanned` 错误码区分）。两种都不得表述为「无匹配」：未扫到的源
    本层无凭据说它没有相关内容（SRS-SEARCH-09）。
    """

    SEARCHED = "searched"  # 有返回记录
    NO_MATCH = "no_match"  # 已完整扫描该来源的全部传入记录且无匹配（唯一可称「无匹配」的状态）
    INCOMPLETE = (
        "incomplete"  # 零返回但不完整（含未扫描）：不得表述为「无匹配」
    )


class QueryRejectionReason(StrEnum):
    """入口校验拒绝码：闭合集合，可安全进日志与错误摘要（不含任何输入值）。"""

    RECORDS_UNBOUNDED = "records_unbounded"  # 不是字面 list/tuple（一次性可迭代对象无法预先计数）
    RECORD_SET_TOO_BROAD = "record_set_too_broad"  # 传入条数超过记录窗口预算
    RECORD_TYPE_INVALID = "record_type_invalid"  # 元素不是 StandardRecord
    FILTER_KEYWORD_INVALID = "filter_keyword_invalid"  # 关键词类型/空白/长度不合
    FILTER_TIME_INVALID = "filter_time_invalid"  # 时间界缺失其一、无时区、不可解析或类型不合
    FILTER_TIME_REVERSED = "filter_time_reversed"  # start 晚于 end（start == end 是合法空区间）
    FILTER_PROJECT_INVALID = "filter_project_invalid"
    FILTER_MAPPINGS_INVALID = "filter_mappings_invalid"  # project_mappings 形态/键范围/值形态不合
    FILTER_SOURCES_INVALID = "filter_sources_invalid"
    FILTER_LIMIT_INVALID = "filter_limit_invalid"
    FILTER_WINDOW_UNBOUNDED = "filter_window_unbounded"  # 三个窗口参数非正整数


#: 固定文案：不拼接 scope、项目、来源、关键词、时间字符串或任何计数以外的输入内容
#: （DES-SEC-01：错误与日志不写查询词、绝对个人路径）。
REJECTION_MESSAGES: dict[QueryRejectionReason, str] = {
    QueryRejectionReason.RECORDS_UNBOUNDED: "拒绝：records 必须是可预先计数的 list 或 tuple。",
    QueryRejectionReason.RECORD_SET_TOO_BROAD: "拒绝：传入记录条数超出本次过滤的记录窗口。",
    QueryRejectionReason.RECORD_TYPE_INVALID: "拒绝：records 含非标准记录元素，未消费任何记录。",
    QueryRejectionReason.FILTER_KEYWORD_INVALID: "拒绝：关键词必须为非空白且不超长度上限的字符串。",
    QueryRejectionReason.FILTER_TIME_INVALID: "拒绝：时间界必须带明确时区；省略 query 时 start 与 end 必须成对给出。",
    QueryRejectionReason.FILTER_TIME_REVERSED: "拒绝：start 晚于 end（相等为合法空区间）。",
    QueryRejectionReason.FILTER_PROJECT_INVALID: "拒绝：project 收窄值形态不合法。",
    QueryRejectionReason.FILTER_MAPPINGS_INVALID: "拒绝：project_mappings 必须是普通 dict，键为本批记录序号、值为非空白且不超长度上限的字符串，条数在限额内。",
    QueryRejectionReason.FILTER_SOURCES_INVALID: "拒绝：sources 必须为受支持来源 ID 的精确列表（形态、条数或取值不合法）。",
    QueryRejectionReason.FILTER_LIMIT_INVALID: "拒绝：limit 必须为 1-100 的整数。",
    QueryRejectionReason.FILTER_WINDOW_UNBOUNDED: "拒绝：记录窗口或扫描预算不是正整数。",
}


class FilterErrorCode(StrEnum):
    """逐来源过滤期错误码：闭合集合，只含类别，不含原值（DES-SEC-01）。

    新增类别只能改本枚举，不得由实现用数据侧字符串临时造键：这些码会进入对外覆盖信息。
    """

    UNKNOWN_SOURCE = "unknown_source"  # 记录来源 ID 不在六个受支持 ID 内：整桶归内部 unknown 诊断桶，不参与匹配
    SOURCE_NOT_SCANNED = (
        "source_not_scanned"
    )  # 通用未扫描：点名该来源但本批无记录，或被任一字符预算拦在门外，一条也没扫
    TIME_UNUSABLE = "time_unusable"  # 该记录时间不可用（无时间/无时区/不可解析/UTC 规范化越界），无法按时序给出结论
    PROJECT_UNATTRIBUTED = (
        "project_unattributed"
    )  # 该记录缺少可用的「序号→项目名」映射（或解析侧已报归属缺口）：既不算命中也不算排除
    LOCATION_UNREADABLE = "location_unreadable"  # 该来源存在位置不可解释的记录，名次与引用串均不外出
    RECORD_FIELD_OUT_OF_BOUNDS = (
        "record_field_out_of_bounds"
    )  # 该来源有命中项的短元数据（会话标识/角色/执行者）带着值但形状不合，只能降为 null 外出
    SCAN_RESOURCE_LIMIT = "scan_resource_limit"  # 该来源**自身**扫描字符预算耗尽，其余记录未看
    GLOBAL_SCAN_LIMIT = (
        "global_scan_limit"
    )  # 本桶被全查询字符预算中止或拦在门外（`global_hit` 不可恢复）：不得称「完整且无匹配」
    RESULT_TRUNCATED = (
        "result_truncated"
    )  # 仅由全查询返回总上限产生：该来源有匹配未返回，返回的是结果子集
    PARSE_INCOMPLETE = "parse_incomplete"  # 解析侧登记了信息损失或归属不可核实（含调用方 stream_partial 申报）


#: 记录时间不可用的解析侧原因码：直接取自 `models.TIMESTAMP_ISSUES` 的值集合（单一事实源，
#: 不手列一份名单）：无论本次有没时间过滤条件，缺时间都是需向调用方说明的缺口。
_MISSING_TIME_ISSUES: frozenset[IssueCode] = frozenset(TIMESTAMP_ISSUES.values())

#: 项目归属不可确定的解析侧原因码（与 `models.IssueCode.UNKNOWN_PROJECT` /
#: `PROJECT_UNVERIFIED` 同集合）：解析侧已自报「这条记录没有可靠归属」，与映射表缺失同方向，
#: 都使该来源不完整。
_PROJECT_ISSUES: frozenset[IssueCode] = frozenset(
    {IssueCode.UNKNOWN_PROJECT, IssueCode.PROJECT_UNVERIFIED}
)


@dataclass(frozen=True)
class MatchRef:
    """一条命中的**引用**：定位与元数据，不含正文（DES-SEC-01 输出有界的本层落点）。

    `record_index` 是调用方输入序列中的 0 起始下标，跨来源唯一：调用方要正文就用自己的下标回到
    原列表，本层不代传；它也是 `project_mappings` 的键。`sequence` 是本层派生的来源内稳定排序位
    （`location.line_no`/`ordinal` 名次取「按 `(line_no, ordinal)` 排序后的位置」，值域≤本来源返回
    条数；用于跨页/跨批对同一来源的顺序做一致性检查，**不充当记录身份**；本来源任一位置不可解释时
    整来源降为 `None`。`timestamp` 是带时区时间规范化到 UTC 后的 ISO 8601；不可用为 `None`，并由
    `time_quality` 说明原因：记录自报 `EXACT` 而本层拿不出可比较的时刻（含 `astimezone` 越界）时，
    引用的质量固定降为 `INVALID`——「exact 却不给时间」是自相矛盾的出示，越界的原值也不外出。`project` 是协调层映射表给出的**策略项目名**（无映射为 `None`），
    不是记录自带的 `record.project`（那是 cwd）。短元数据在返回前做形态判定，形状不合即降为
    `None`（是否另记错误码逐字段不同，见模块文档）——本层只剥首尾空白，不改写值、不按长度截断，
    也不把不可信形状的原值外出。
    """

    record_index: int
    sequence: int | None
    source: str
    session_id: str | None
    role: str | None
    executor: str | None
    timestamp: str | None
    time_quality: TimeQuality
    project: str | None
    project_quality: ProjectQuality
    location: str | None

    def as_public_dict(self) -> dict[str, Any]:
        return {
            "record_index": self.record_index,
            "sequence": self.sequence,
            "source": self.source,
            "session_id": self.session_id,
            "role": self.role,
            "executor": self.executor,
            "timestamp": self.timestamp,
            "time_quality": self.time_quality.value,
            "project": self.project,
            "project_quality": self.project_quality.value,
            "location": self.location,
        }


@dataclass(frozen=True)
class SourceCoverage:
    """一个来源在本次过滤中的覆盖结论（DES-API-01 `coverage` 的本层子集）。

    `matched_count` 是该来源**已扫描记录中**的全部匹配条数（不受总返回上限 `limit` 影响，无上限整数），
    `returned_count` 是实际返回条数，两者不等即 `result_truncated` 已计入 `filter_errors`（**只有**全查询
    总上限裁掉才记它；扫描提前中止未看到的记录不算截断，记 `scan_resource_limit`/`global_scan_limit`
    并计入 `skipped_count`）。`records_scanned` 与 `scan_chars` 是本层实际消费的量；`skipped_count` 是本层
    **没看到**的传入记录数（`传入总数 - records_scanned`，由任一字符预算触限或内部 `unknown`
    诊断桶整桶不参与匹配产生），“没看完”因此有一个可加总的
    下限，而不是只看到一个布尔值。点名但本批无记录的来源：`records_scanned=0`、`partial=True`、
    错误码 `source_not_scanned`、状态 `incomplete`（不是 `no_match`）；`unknown` 桶不记这个码，它只记
    `unknown_source` 且三个计数全为 0。`quality_issues` 是
    `issue_code=count` 形式的逐码计数（键取自 `IssueCode`，无数据侧字符串）：它们与 `partial` 同源——
    不降级覆盖的只有 `models.NON_PARTIAL_ISSUES` 里的三类，其余一律既计数又使 `partial` 为真。
    """

    source: str
    status: CoverageStatus
    matched_count: int
    returned_count: int
    records_scanned: int
    skipped_count: int
    scan_chars: int
    partial: bool
    filter_errors: tuple[FilterErrorCode, ...]
    quality_issues: tuple[str, ...]
    reason: str

    def as_public_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "status": self.status.value,
            "matched_count": self.matched_count,
            "returned_count": self.returned_count,
            "records_scanned": self.records_scanned,
            "skipped_count": self.skipped_count,
            "scan_chars": self.scan_chars,
            "partial": self.partial,
            "filter_errors": [code.value for code in self.filter_errors],
            "quality_issues": list(self.quality_issues),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class FilterWindow:
    """本次过滤实际生效的窗口（构造期把硬钳与拒绝一次做完，扫描期不再判参数）。

    `limit` 是**全查询返回总条数**上限（不是每源）；`max_records` 是进入过滤的记录条数；
    `max_scan_chars` 是**每来源**扫描字符预算；`max_total_scan_chars` 是**全查询**字符预算。
    四项都可由调用方下调，但不可越过本模块的硬钳；任一为非 `None` 的非正整数即 `rejected=True`
    （一个没生效的上限比没有上限更危险）。两个字符预算共限，不是二选一。
    """

    limit: int
    max_records: int
    max_scan_chars: int
    max_total_scan_chars: int
    rejected: bool = False
    reason: QueryRejectionReason | None = None

    @classmethod
    def create(
        cls,
        limit: object,
        max_records: object,
        max_scan_chars: object,
        max_total_scan_chars: object,
    ) -> FilterWindow:
        """校验并钳制四个窗口参数；不合法时只给固定拒绝码。"""
        if isinstance(limit, bool) or not isinstance(limit, int):
            return _WINDOW_REJECTED[QueryRejectionReason.FILTER_LIMIT_INVALID]
        if not LIMIT_MIN <= limit <= LIMIT_MAX:
            return _WINDOW_REJECTED[QueryRejectionReason.FILTER_LIMIT_INVALID]
        window = _positive_clamped(max_records, MAX_FILTERED_RECORDS, MAX_FILTERED_RECORDS_HARD_LIMIT)
        if window is None:
            return _WINDOW_REJECTED[QueryRejectionReason.FILTER_WINDOW_UNBOUNDED]
        budget = _positive_clamped(max_scan_chars, MAX_SCAN_CHARS, MAX_SCAN_CHARS_HARD_LIMIT)
        if budget is None:
            return _WINDOW_REJECTED[QueryRejectionReason.FILTER_WINDOW_UNBOUNDED]
        total = _positive_clamped(
            max_total_scan_chars, MAX_TOTAL_SCAN_CHARS, MAX_TOTAL_SCAN_CHARS_HARD_LIMIT
        )
        if total is None:
            return _WINDOW_REJECTED[QueryRejectionReason.FILTER_WINDOW_UNBOUNDED]
        return cls(
            limit=limit,
            max_records=window,
            max_scan_chars=budget,
            max_total_scan_chars=total,
        )

    def as_public_dict(self) -> dict[str, Any]:
        return {
            "limit": self.limit,
            "max_records": self.max_records,
            "max_scan_chars": self.max_scan_chars,
            "max_total_scan_chars": self.max_total_scan_chars,
        }


#: 拒绝用的窗口哨兵：只携带结论，不携带任何参数值。
_WINDOW_REJECTED: dict[QueryRejectionReason, FilterWindow] = {
    reason: FilterWindow(
        limit=DEFAULT_LIMIT,
        max_records=MAX_FILTERED_RECORDS,
        max_scan_chars=MAX_SCAN_CHARS,
        max_total_scan_chars=MAX_TOTAL_SCAN_CHARS,
        rejected=True,
        reason=reason,
    )
    for reason in (
        QueryRejectionReason.FILTER_LIMIT_INVALID,
        QueryRejectionReason.FILTER_WINDOW_UNBOUNDED,
    )
}


@dataclass(frozen=True)
class SourceFilter:
    """已校验的过滤条件（由 `scan_filter` 在入口一次构造，扫描期只读）。

    `project` 是调用方点名的**策略项目名**，比较用精确相等（不 `casefold`、不归一）：它必须来自
    策略配置而不是路径推测，折叠大小写等于替配置发明一条它没声明过的等价关系，还会让两个只差
    大小写的已批准项目互相命中。`None` 表示不点名项目（仍需映射才能认定归属）。
    `sources` 为 `None` 表示不点名；点名时集合只会是六个精确 ID（入口已拒 `unknown` 与集合外值）。
    两界都在且 `start == end` 时区间自然为空（左闭右开），所有带时间的记录均不命中，本层不另设哨兵。
    """

    keyword: str | None
    start: datetime | None
    end: datetime | None
    project: str | None
    sources: frozenset[str] | None
    rejected: bool = False
    reason: QueryRejectionReason | None = None

    @property
    def time_restricted(self) -> bool:
        """本次是否带了时间条件（任一端存在即算：单边区间也是合法的有界收窄）。"""
        return self.start is not None or self.end is not None


@dataclass(frozen=True)
class ScanFilterOutcome:
    """一次有界过滤的结果：引用 + 逐来源覆盖，**没有正文通道**。

    `rejected` 为真时 `matches`/`coverage` 均为空元组：入口校验失败不返回任何部分结论。
    `total_matched` 是各来源 `matched_count` 之和（**已扫描记录中**的全部匹配数，不是返回数），
    `returned_count` 是 `matches` 长度（永远 ≤ `limit`，它是全查询总上限），`total_scanned` 是各来源
    实际消费条数之和，`skipped_records` 是全查询未扫描的传入记录数，`scan_chars` 是本层读取的总字符数。
    `truncated` 只表示**有来源因全查询返回总上限少给了返回条目**（即 `result_truncated` 的唯一来源）；
    扫描预算触限看 `global_scan_limit_hit` 与逐来源 `filter_errors` 里的 `scan_resource_limit`/
    `global_scan_limit`：被裁掉的是返回条目，和被跳过未扫描的记录是两回事，不合并成一个布尔。

    `unscanned_sources` 列出点名但未扫到任何记录的来源（最多六个）：它非空即表示「还有源没扫」，
    调用方不得把本次结果当作覆盖全部点名单。零分组且未点名时 `coverage` 为空，因此
    `complete` 直接为假：没有任何逐源行可作证时，「完整」就是未证明的说法。

    `skipped_records` 是本层**未扫到**的记录数，只算「本次该扫」的那部分（进入覆盖的桶），
    预算未触限时受支持桶不贡献缺口；内部 `unknown` 诊断桶整桶不扫，因此计入这里——它是
    「本层没看」的记录，不是「看了但不匹配」。
    `scan_chars` 是本层读取的总字符数（各源 `scan_chars` 之和）。

    `declared_partial` 回显调用方的 `stream_partial` 申报值。零分组时没有逐来源行可携带该信号，
    不回显就是静默丢掉一个保守结论。
    """

    rejected: bool
    reason: QueryRejectionReason | None
    matches: tuple[MatchRef, ...]
    coverage: tuple[SourceCoverage, ...]
    total_matched: int
    total_scanned: int
    truncated: bool
    declared_partial: bool = False
    global_scan_limit_hit: bool = False
    skipped_records: int = 0
    scan_chars: int = 0
    unscanned_sources: tuple[str, ...] = ()

    @property
    def returned_count(self) -> int:
        return len(self.matches)

    @property
    def complete(self) -> bool:
        """本层可见部分全部完整，且每个点名来源都有已扫描的行（拒绝态同样为假）。

        它为真仍**不等于已授权发布**：项目映射只是输入契约，来源绑定与会话身份核对不在本层，
        上层需自行叠加 `ParseStats.partial` 与授权、遮蔽结论。
        """
        if (
            self.rejected
            or self.declared_partial
            or self.global_scan_limit_hit
            or self.unscanned_sources
            or not self.coverage
        ):
            return False
        return not any(source.partial for source in self.coverage)

    def as_public_dict(self) -> dict[str, Any]:
        return {
            "rejected": self.rejected,
            "reason": self.reason.value if self.reason else None,
            "returned_count": self.returned_count,
            "total_matched": self.total_matched,
            "total_scanned": self.total_scanned,
            "skipped_records": self.skipped_records,
            "scan_chars": self.scan_chars,
            "truncated": self.truncated,
            "global_scan_limit_hit": self.global_scan_limit_hit,
            "unscanned_sources": list(self.unscanned_sources),
            "complete": self.complete,
            "declared_partial": self.declared_partial,
            "matches": [match.as_public_dict() for match in self.matches],
            "coverage": [source.as_public_dict() for source in self.coverage],
        }


def scan_filter(
    records: Sequence[StandardRecord],
    *,
    query: str | None = None,
    start: datetime | str | None = None,
    end: datetime | str | None = None,
    project: str | None = None,
    project_mappings: dict[int, str] | None = None,
    sources: Sequence[str] | None = None,
    limit: int = DEFAULT_LIMIT,
    max_records: int | None = None,
    max_scan_chars: int | None = None,
    max_total_scan_chars: int | None = None,
    stream_partial: bool = False,
    completed_sources: Sequence[str] | None = None,
) -> ScanFilterOutcome:
    """对调用方传入的标准记录做有界关键词/时间/项目过滤，并汇总逐来源覆盖。

    关键词与时间至少给一个（与协议层 `search_sessions` 同一约定）：两者都不给就是「把整批记录
    按来源倒出来」，那既不是检索，也让 `limit` 变成一个随机的子集选取，覆盖信息无法表达其含义。
    `sources` 只做收窄，不放宽任何判据；点名集合只会是六个精确 ID（入口已拒 `unknown`）。来源标识
    不可识别的记录落入内部 `unknown` 诊断桶：该桶整桶不参与匹配（不占返回额度也不动用扫描预算），
    只携一个 `unknown_source` 的覆盖行，传入记录全部计未扫描——无论是否点名都不会产出结果。

    **项目归属靠 `project_mappings`**（协调层显式提供的「记录序号 → 已映射策略项目名」）：
    `record.project` 是 cwd，与策略项目名不是同一种值，本层不拿它做任何归属判定。缺映射的记录
    不论是否点名 `project` 一律**排除并使来源 `partial`**（记 `project_unattributed`）：判不出归属
    既不能算命中也不能算不命中。点名 `project` 时与映射名**精确相等**比较（不折叠大小写、不做
    路径归一）。这张表只是输入契约：命中不证明授权，也不证明来源绑定（DES-API-01 发布边界），
    协调层未完成身份核对与遮蔽时仍不得发布。

    时间边界**只**接受带时区的 `datetime` 或 ISO 8601 字符串（字符串走 `models.normalize_timestamp`，
    含长度上限），两者都在入口规范化到 UTC；数字纪元与 `bool` 不是合法边界（单位无法证明）、
    无时区也照样拒绝，不回填本地时区、不使用文件 mtime。有 `query` 时允许只给
    一端（给出的那端仍必须带时区）；无 `query` 时 `start`/`end` 必须成对给出。区间左闭右开，
    `start == end` 返回 0 命中而不是报错。记录侧只让能规范化到 UTC 的 `EXACT` 时刻参与比较；
    自报 `EXACT` 却越界拿不出时刻的记录固定降级为 `INVALID` 并记 `time_unusable`，不抛异常也不回显原值。

    本函数**不判断授权**：不接受 `scope`，不看调用方的任何「已授权」标志，也不因被调用而放行
    正文。返回的是引用与覆盖结论，正文与片段不在本层的输出通道里（见模块文档）。

    `stream_partial` 是调用方（读取/解析层）登记「这批记录背后的流没读完或有坏行」的唯一通道：
    坏行不产出记录，本层无法自行发现。它为真时**每个来源**都记 `parse_incomplete` 且 `partial`
    为真（只会收紧、不会放宽）；省略它只表示调用方未申报，**不构成本层对完整性的证明**，
    上层仍需叠加 `ParseStats.partial` 判断（两者口径独立，见模块文档）。

    `completed_sources` 是受信任上游提供的空流证据：仅当上游已确认某个具名来源完整扫描、但
    没有产出任何 `StandardRecord` 时，才可列入。它只把该来源的空桶解释为已扫描的 `no_match`；
    本参数本身不构成证明或授权，也不能放宽 `stream_partial`。普通调用方应省略，保持「无记录即
    未扫描」的保守默认。
    """
    window = FilterWindow.create(limit, max_records, max_scan_chars, max_total_scan_chars)
    if window.rejected:
        return _reject(window.reason)
    # 申报位只按真/假解释，不看类型：非 bool 的真值（如 1、非空集合）同样按「已申报不完整」处理，
    # 因为这里只有收紧方向——把它当成 False 会静默丢掉一个保守信号。
    stream_partial = bool(stream_partial)

    if not isinstance(records, (list, tuple)):
        return _reject(QueryRejectionReason.RECORDS_UNBOUNDED)
    if len(records) > window.max_records:
        # 消费之前判窗口：这是驻留内存的唯一有效上界（扫描预算不阻止「已匹配未返回」的引用累积）。
        return _reject(QueryRejectionReason.RECORD_SET_TOO_BROAD)

    mappings, mapping_failure = _build_mappings(project_mappings, len(records))
    if mapping_failure is not None:
        return _reject(mapping_failure)

    completed, completed_failure = _build_completed_sources(completed_sources)
    if completed_failure is not None:
        return _reject(completed_failure)

    conditions = _build_filter(query, start, end, project, sources)
    if conditions.rejected:
        return _reject(conditions.reason)

    buckets: dict[str, list[tuple[int, StandardRecord]]] = {}
    for index, record in enumerate(records):
        # 元素类型或字段形状不合是一次误用，不是一批坏数据：整批拒绝，不返回任何部分结果。
        if not isinstance(record, StandardRecord) or not _record_shape_ok(record):
            return _reject(QueryRejectionReason.RECORD_TYPE_INVALID)
        buckets.setdefault(_source_key(record.source), []).append((index, record))

    state = _ScanState(
        stream_partial=stream_partial,
        global_left=window.max_total_scan_chars,
        return_left=window.limit,
    )
    matches: list[MatchRef] = []
    coverage: list[SourceCoverage] = []
    unscanned: list[str] = []
    for key in _coverage_order(conditions.sources, buckets, completed):
        source_matches, source_coverage = _filter_bucket(
            key,
            buckets.get(key),
            conditions,
            mappings,
            window,
            state,
            completed_empty=key in completed and not buckets.get(key),
        )
        matches.extend(source_matches)
        coverage.append(source_coverage)
        if (
            FilterErrorCode.SOURCE_NOT_SCANNED in source_coverage.filter_errors
            and key in _KNOWN_SOURCE_KEYS
        ):
            # 零条记录的已完成空桶没有该错误；其它一条也未扫到的情况仍如实登记。
            unscanned.append(key)

    return ScanFilterOutcome(
        rejected=False,
        reason=None,
        matches=tuple(matches),
        coverage=tuple(coverage),
        total_matched=sum(row.matched_count for row in coverage),
        total_scanned=state.total_scanned,
        truncated=any(
            FilterErrorCode.RESULT_TRUNCATED in row.filter_errors for row in coverage
        ),
        declared_partial=stream_partial,
        global_scan_limit_hit=state.global_hit,
        skipped_records=state.eligible - state.total_scanned,
        scan_chars=state.total_chars,
        unscanned_sources=tuple(unscanned),
    )


def _reject(reason: QueryRejectionReason | None) -> ScanFilterOutcome:
    """拒绝出口：不返回任何记录信息，也不回显任何调用方输入。"""
    return ScanFilterOutcome(
        rejected=True,
        reason=reason,
        matches=(),
        coverage=(),
        total_matched=0,
        total_scanned=0,
        truncated=False,
    )


def _build_mappings(
    mappings: object,
    record_count: int,
) -> tuple[dict[int, str], QueryRejectionReason | None]:
    """入口一次性校验「记录序号 → 已映射策略项目名」表；失败时只给固定拒绝码。

    只接受普通 `dict`：`Mapping` 的 `__getitem__` 可以由任意实现提供，本层需要在消费之前整表判长。
    键必须是本批范围内的整数序号（`bool` 不算整数），值必须是剥首尾空白后非空、
    ≤ `MAX_PROJECT_VALUE_CHARS` 的 `str`：本层不拿映射表猜未提供的对应关系，也不替它补默认项目名。
    不校策略合法性（`project_unknown` 属于 `policy.py`）：一张长得对的表仍然可能指向未批准的项目名，
    那是调用方的核对职责。原字典不被修改（返回一份新的）。
    """
    if mappings is None:
        return {}, None
    # `isinstance` 供类型窄化，`__class__` 真类判定排除 `defaultdict` 一类会自动补键的子类：
    # 一张本层以为只有 N 项的表可以在读取时变大。
    if not isinstance(mappings, dict) or mappings.__class__ is not dict:
        return {}, QueryRejectionReason.FILTER_MAPPINGS_INVALID
    if len(mappings) > MAX_RECORD_MAPPINGS:
        return {}, QueryRejectionReason.FILTER_MAPPINGS_INVALID
    accepted: dict[int, str] = {}
    for key, value in mappings.items():
        if isinstance(key, bool) or not isinstance(key, int) or not 0 <= key < record_count:
            return {}, QueryRejectionReason.FILTER_MAPPINGS_INVALID
        if not isinstance(value, str):
            return {}, QueryRejectionReason.FILTER_MAPPINGS_INVALID
        name = value.strip()
        if not name or len(name) > MAX_PROJECT_VALUE_CHARS:
            return {}, QueryRejectionReason.FILTER_MAPPINGS_INVALID
        accepted[key] = name
    return accepted, None


def _build_completed_sources(
    sources: object,
) -> tuple[frozenset[str], QueryRejectionReason | None]:
    """入口校验上游申报的已完成来源集合；它只给空桶提供覆盖行，不授予读取或发布权。"""
    if sources is None:
        return frozenset(), None
    if not isinstance(sources, (list, tuple)) or len(sources) > MAX_SOURCES_PER_QUERY:
        return frozenset(), QueryRejectionReason.FILTER_SOURCES_INVALID
    accepted: set[str] = set()
    for name in sources:
        if (
            not isinstance(name, str)
            or len(name) > MAX_SOURCE_ID_CHARS
            or name not in _KNOWN_SOURCE_KEYS
        ):
            return frozenset(), QueryRejectionReason.FILTER_SOURCES_INVALID
        accepted.add(name)
    return frozenset(accepted), None


def _coverage_order(
    named: frozenset[str] | None,
    buckets: dict[str, list[tuple[int, StandardRecord]]],
    completed: frozenset[str],
) -> list[str]:
    """本次要产出覆盖行的来源，固定顺序：先 `SUPPORTED_SOURCES`，再内部 `unknown` 桶。

    点名了哪些受支持来源就出哪些行（即使本批无记录：那一行是「未扫描」而不是 `no_match`）。
    未点名时：本批有记录的受支持来源成行，`unknown` 桶只在它非空时成行（不点名也不伪造空行）。
    本函数不改变分组内容，只决定哪些桶会得到一次覆盖结论。
    """
    if named is not None:
        keys = [key for key in SUPPORTED_SOURCES if key in named]
        if _UNKNOWN_SOURCE_KEY in buckets:
            keys.append(_UNKNOWN_SOURCE_KEY)
        return keys
    keys = [key for key in SUPPORTED_SOURCES if key in buckets or key in completed]
    if _UNKNOWN_SOURCE_KEY in buckets:
        keys.append(_UNKNOWN_SOURCE_KEY)
    return keys


@dataclass
class _ScanState:
    """一次查询内逐源共享的预算余量（全查询字符预算、总返回额度与总量计数）。

    `global_left`/`return_left` 随扫描递减：两道预算与总上限都是**全查询**口径，所以下一个来源
    从上一个来源剩下的额度接着用，而不是各自拿到一份全额。`global_hit` 一旦置位就是**不可恢复
    状态**：后续每个桶在逐条额度比较之前先守住它，连正文为空的记录也不扫——只比额度会在
    `global_left == 0` 时把 `size=0` 放行，让「已用尽」与「还在扫」同时成立。计数只累加已完成扫描的量。
    """

    stream_partial: bool
    global_left: int
    return_left: int
    global_hit: bool = False
    total_scanned: int = 0
    total_chars: int = 0
    eligible: int = 0


def _positive_clamped(value: object, default: int, hard_limit: int) -> int | None:
    """把可选窗口值解释为 `int`：`None` 取默认，非正整数返回 `None`（由调用方拒绝），超硬钳取硬钳。"""
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return min(value, hard_limit)


def _key_of(value: str) -> str:
    """统一的匹配键归一：`casefold`。

    关键词与记录正文走同一个函数，因此「匹配规则一致」这条契约（DES-API-01）不依赖两处实现
    同步。不做全半角/变音归一、不做分词、不用正则。
    """
    return value.casefold()


def _build_filter(
    query: object,
    start: object,
    end: object,
    project: object,
    sources: object,
) -> SourceFilter:
    """一次性校验全部过滤条件；任一项不合只给固定拒绝码（不回显原值）。"""
    if query is None:
        keyword = None
    elif not isinstance(query, str):
        return _filter_rejected[QueryRejectionReason.FILTER_KEYWORD_INVALID]
    else:
        text = query.strip()
        if not text or len(text) > MAX_KEYWORD_CHARS:
            return _filter_rejected[QueryRejectionReason.FILTER_KEYWORD_INVALID]
        keyword = _key_of(text)

    if start is None or end is None:
        # 有 query 时允许只给一端（给出的那端仍必须带时区）；两者都不给就是无界扫描，已在上面拒掉。
        if keyword is None:
            # 只靠时间收窄的查询不给两端 = 开放另一端的无界时间扫描：拒绝而不补默认值。
            return _filter_rejected[QueryRejectionReason.FILTER_TIME_INVALID]
        lower = None if start is None else _bound(start)
        upper = None if end is None else _bound(end)
        if (start is not None and lower is None) or (end is not None and upper is None):
            return _filter_rejected[QueryRejectionReason.FILTER_TIME_INVALID]
    else:
        lower = _bound(start)
        upper = _bound(end)
        if lower is None or upper is None:
            return _filter_rejected[QueryRejectionReason.FILTER_TIME_INVALID]
        if lower > upper:
            return _filter_rejected[QueryRejectionReason.FILTER_TIME_REVERSED]

    project_value: str | None = None
    if project is not None:
        if not isinstance(project, str):
            return _filter_rejected[QueryRejectionReason.FILTER_PROJECT_INVALID]
        name = project.strip()
        if not name or len(name) > MAX_PROJECT_VALUE_CHARS:
            return _filter_rejected[QueryRejectionReason.FILTER_PROJECT_INVALID]
        # 不做 casefold：与映射名精确相等才是本层的项目判据（见 SourceFilter 文档）。
        project_value = name

    named: frozenset[str] | None = None
    if sources is not None:
        too_many = (
            isinstance(sources, (list, tuple)) and len(sources) > MAX_SOURCES_PER_QUERY
        )
        if not isinstance(sources, (list, tuple)) or not sources or too_many:
            return _filter_rejected[QueryRejectionReason.FILTER_SOURCES_INVALID]
        keys: list[str] = []
        for name in sources:
            # 精确 ID 白名单：不剥空白、不折叠大小写（`PI` 与 ` unknown` 都不是合法的来源指定），
            # 集合外的值（含内部 `unknown` 桶名）一律拒：它不是一个可请求的来源。长度先于成员
            # 判定：避开先哈希一个不受控长串再做无望的比对。
            if (
                not isinstance(name, str)
                or len(name) > MAX_SOURCE_ID_CHARS
                or name not in _KNOWN_SOURCE_KEYS
            ):
                return _filter_rejected[QueryRejectionReason.FILTER_SOURCES_INVALID]
            keys.append(name)
        named = frozenset(keys)

    return SourceFilter(
        keyword=keyword,
        start=lower,
        end=upper,
        project=project_value,
        sources=named,
    )


#: 条件校验的拒绝哨兵：只携带结论。
_filter_rejected: dict[QueryRejectionReason, SourceFilter] = {
    reason: SourceFilter(
        keyword=None,
        start=None,
        end=None,
        project=None,
        sources=None,
        rejected=True,
        reason=reason,
    )
    for reason in (
        QueryRejectionReason.FILTER_KEYWORD_INVALID,
        QueryRejectionReason.FILTER_TIME_INVALID,
        QueryRejectionReason.FILTER_TIME_REVERSED,
        QueryRejectionReason.FILTER_PROJECT_INVALID,
        QueryRejectionReason.FILTER_SOURCES_INVALID,
    )
}


def _utc(moment: datetime) -> datetime | None:
    """把带时区时刻规范化到 UTC；越界（极端年份加减偏移）返回 `None`，不让整次查询抛异常。"""
    try:
        return moment.astimezone(UTC)
    except (OverflowError, ValueError):
        return None


def _bound(value: object) -> datetime | None:
    """把一个时间界解释为 UTC 带时区 datetime；不可用返回 `None`（不回填时区、不猜单位）。

    只接受 `datetime` 与 ISO 8601 字符串：数字与 `bool` 在这里不是合法边界——`normalize_timestamp`
    会按量级猜秒/毫秒/微秒，而一个裸数字无法证明调用方想要哪一种单位，所以不交给它。
    """
    if isinstance(value, datetime):
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            return None
        return _utc(value)
    if not isinstance(value, str):
        return None
    parsed, quality = normalize_timestamp(value)
    if quality is not TimeQuality.EXACT or parsed is None:
        return None
    return _utc(parsed)


def _record_moment(record: StandardRecord) -> datetime | None:
    """记录自带时间的可比时刻（UTC）；自报非 `EXACT`、形状不合或规范化越界都返回 `None`。

    时间判据只在这里一处：`_judge` 的区间比较与 `_match_ref` 的时间外出都走它，因此不会
    出现「比较时能用、出示时拿不出」（或反过来）的分歧。
    """
    if record.time_quality is not TimeQuality.EXACT:
        return None
    moment = record.timestamp
    if not isinstance(moment, datetime) or moment.tzinfo is None:
        return None
    if moment.tzinfo.utcoffset(moment) is None:
        return None
    return _utc(moment)


def _time_degraded(record: StandardRecord) -> bool:
    """该记录自报 `EXACT` 而本层拿不出可比较的 UTC 时刻：引用需固定降级并计入覆盖缺口。"""
    return record.time_quality is TimeQuality.EXACT and _record_moment(record) is None


def _source_key(value: object) -> str:
    """记录来源 ID → 分组键；不受支持的取值一律归入内部 `unknown` 桶（不冒充六类来源）。

    这里**不剥空白、不折叠大小写**：分组键必须与 `sources` 入口的精确 ID 判据同一口径，否则
    一条 `" pi"` 记录会被归到 `pi` 桶，而调用方永远无法点名那个桶（或反之）。长度判据在成员判定
    之前：不为一条携带超长 `source` 的记录去哈希任意长的串。
    """
    if isinstance(value, str) and len(value) <= MAX_SOURCE_ID_CHARS and value in _KNOWN_SOURCE_KEYS:
        return value
    return _UNKNOWN_SOURCE_KEY


def _short_text(value: object, limit: int) -> str | None:
    """短元数据的形态判定：非 `str`、剥首尾空白后为空或超限时返回 `None`。

    通过判定时返回**剥过首尾空白**的原值：不按长度截断（前缀仍可能是可辨认的原值片段）、
    不做大小写或路径归一（那会篡改调用方的标识）。
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > limit:
        return None
    return text


def _location_form(location: object) -> tuple[int, int] | None:
    """校验 `SourceLocation` 的可解释形状，返回 `(line_no, ordinal)`；不可解释返回 `None`。"""
    if not isinstance(location, SourceLocation):
        return None
    line_no = location.line_no
    ordinal = location.ordinal
    if isinstance(line_no, bool) or not isinstance(line_no, int) or not 1 <= line_no <= MAX_LINE_NO:
        return None
    if isinstance(ordinal, bool) or not isinstance(ordinal, int) or not 0 <= ordinal <= MAX_MATCH_ORDINAL:
        return None
    return line_no, ordinal


def _sequence_of(keep: Sequence[tuple[int, StandardRecord]]) -> list[int | None]:
    """按原文位置给该来源返回的命中派生**名次**；任一位置不可解释则整来源降为无名次。

    名次取「按 `(行号, 同行产出序号)` 排序后的位置」，值域就是该来源返回条数（受全查询总上限
    `limit` 约束，≤ 100），因此不会像直接拿行号当序号那样拼出无界的数。部分命中有名次、部分没有
    会让上层误以为顺序完整，所以判据是整来源一致：要么都有名次，要么全为 `None`。
    """
    ranks: list[tuple[int, int, int]] = []
    for index, record in keep:
        form = _location_form(record.location)
        if form is None:
            return [None] * len(keep)
        ranks.append((form[0], form[1], index))
    order = {pair[2]: position for position, pair in enumerate(sorted(ranks))}
    return [order[index] for index, _ in keep]


def _record_shape_ok(record: StandardRecord) -> bool:
    """记录形状判据（入口只跑一次）：只放行字段类型可预期的记录。

    数据类不在运行时校类型，所以下列字段必须在这里守住：`text` 是扫描预算与关键词匹配的
    唯一可变长字段；`issues` 的元素只会以 `issue.value` 进入对外 `quality_issues`，非枚举元素
    会把数据侧字符串带进公开计数（与 `ParseStats.note()` 同一取向）；两个质量字段是本层「不猜」
    判据的依据；`location` 决定位置引用串与名次。`location.line_no`/`ordinal` 的取值范围单独由
    `_location_form` 判（它只影响名次与引用串，不影响过滤结论）。
    """
    if not isinstance(record.text, str):
        return False
    if not isinstance(record.time_quality, TimeQuality):
        return False
    if not isinstance(record.project_quality, ProjectQuality):
        return False
    if not isinstance(record.location, SourceLocation):
        return False
    issues = record.issues
    if not isinstance(issues, tuple):
        return False
    return all(isinstance(issue, IssueCode) for issue in issues)


def _filter_bucket(
    key: str,
    entries: Sequence[tuple[int, StandardRecord]] | None,
    conditions: SourceFilter,
    mappings: dict[int, str],
    window: FilterWindow,
    state: _ScanState,
    *,
    completed_empty: bool = False,
) -> tuple[list[MatchRef], SourceCoverage]:
    """过滤一个来源桶，产出返回引用与该来源的覆盖结论，并逐桶消耗全查询额度。

    固定判定顺序（顺序即语义）：⓪`global_hit` 已置位或本桶是内部 `unknown` 诊断桶即整桶不扫；
    ①正文与逐源/全查询两道预算比较（任一不够即 `break`，本条与其后记录一概不看、**不计入 scanned**）；
    ②预算内才累计字符数与扫描条数；③登记该记录的解析侧原因码；④`_judge` 逐条过滤判定；
    ⑤引用生成前先统一时间/位置/短元数据判据（`_time_degraded` 与 `_match_ref` 共用同一判据），
    命中只在全查询返回额度内保留引用，额度外的**只计数不留引用**。
    本桶不存在「先把全部命中装进列表再切前 N 条」的中间态，所以额外驻留由 `limit` 封顶，
    不随匹配数增长。
    """
    rows: tuple[tuple[int, StandardRecord], ...] = tuple(entries) if entries else ()
    errors: list[FilterErrorCode] = []
    quality: dict[str, int] = {}
    if state.stream_partial:
        # 调用方申报的流级不完整（坏行不产出记录，本层看不到）：整来源标出不完整。
        _note_error(errors, FilterErrorCode.PARSE_INCOMPLETE)
    if not rows:
        # 默认点名却无记录仍是未扫描。仅在调用方给出已完成空流证据时，才可报告完整 no_match；
        # stream_partial 已在上方登记，因此坏流不会被此证据覆盖。
        if not completed_empty:
            _note_error(errors, FilterErrorCode.SOURCE_NOT_SCANNED)
        return [], _coverage(key, errors, quality, 0, 0, 0, 0, 0)
    if key == _UNKNOWN_SOURCE_KEY:
        # 诊断桶，不是可匹配集：整桶不做逐条判定、不动两道字符预算、不占返回额度，传入记录
        # 全部计未扫描/跳过。错误码是去重集合，登记一次 unknown_source 就够，不逐条伪造诊断；
        # 也不另记 source_not_scanned——这里的缺口是「来源不可识别」，原因只有一个准确的码。
        _note_error(errors, FilterErrorCode.UNKNOWN_SOURCE)
        state.eligible += len(rows)
        return [], _coverage(key, errors, quality, 0, 0, 0, len(rows), 0)
    state.eligible += len(rows)

    scanned = 0
    consumed_chars = 0
    matched_total = 0
    keep: list[tuple[int, StandardRecord]] = []
    budget = window.max_scan_chars
    for index, record in rows:
        if state.global_hit:
            # 全查询预算是不可恢复状态，必须在逐条额度比较之前守住（见 _ScanState）：
            # 本桶一条也没扫，未扫部分由下面的 source_not_scanned 与 skipped 计数承担。
            _note_error(errors, FilterErrorCode.GLOBAL_SCAN_LIMIT)
            break
        size = len(record.text)
        if consumed_chars + size > budget:
            # 逐源预算耗尽：剩下的记录可能匹配，因此该来源不完整。
            _note_error(errors, FilterErrorCode.SCAN_RESOURCE_LIMIT)
            break
        if size > state.global_left:
            # 全查询预算耗尽：本条不扫、不计数。不顶替该源自身的 scan_resource_limit（两道预算是
            # 不同的限），但本桶确实未扫完，因此逐源仍记一个自己的码：行级 partial 不得因
            # 「只碰上了全查询限」而消失（SRS-SEARCH-09 受限中止）。
            state.global_hit = True
            _note_error(errors, FilterErrorCode.GLOBAL_SCAN_LIMIT)
            break
        consumed_chars += size
        state.global_left -= size
        scanned += 1

        for issue in record.issues:
            if issue in NON_PARTIAL_ISSUES:
                # 空行、本身无文本、已识别的非检索正文块：不降级覆盖（与解析侧同一口径）。
                continue
            # 其余类别都是解析侧自报的信息损失：既进解释性计数，也使本来源不完整。
            # 单一事实源是 `models.NON_PARTIAL_ISSUES`，本层不再手列一份名单以免与解析侧漂移。
            quality[issue.value] = quality.get(issue.value, 0) + 1
            _note_error(errors, FilterErrorCode.PARSE_INCOMPLETE)
            if issue in _MISSING_TIME_ISSUES:
                _note_error(errors, FilterErrorCode.TIME_UNUSABLE)
            if issue in _PROJECT_ISSUES:
                _note_error(errors, FilterErrorCode.PROJECT_UNATTRIBUTED)

        if not _judge(index, record, conditions, mappings, errors):
            continue
        matched_total += 1
        if state.return_left > 0:
            keep.append((index, record))
            state.return_left -= 1

    state.total_scanned += scanned
    state.total_chars += consumed_chars
    if scanned == 0:
        # 一条也没扫到（本批未交出该源、全查询额度在进入本桶前已用尽、或首条就超预算）：
        # 不补这一笔就会拿一个空错误集把该源报成 `no_match`（零返回且「完整」）。
        _note_error(errors, FilterErrorCode.SOURCE_NOT_SCANNED)
    if matched_total > len(keep):
        # 只有全查询返回额度用尽才会出现「匹配数 > 保留数」：被裁掉的是返回条目，逐源如实记
        # result_truncated。扫描提前中止未看到的记录不在此列（那时 matched_total 根本没数到它们）。
        _note_error(errors, FilterErrorCode.RESULT_TRUNCATED)

    # 位置不可解释时名次与引用串均不外出，只拿掉名次、不拿掉命中本身（名次不是发布条件）。
    # 必须在覆盖结论构造**之前**登记，否则该错误码只影响展示、不影响完整性。
    ranks = _sequence_of(keep)
    if keep and ranks[0] is None:
        _note_error(errors, FilterErrorCode.LOCATION_UNREADABLE)
    if any(_time_degraded(record) for _, record in keep):
        # 自报 EXACT 却拿不出可比较的 UTC 时刻：_match_ref 会用同一判据把引用固定降级，这里在
        # 生成引用**之前**登记同一个缺口（先定判据、后出示），否则展示与统计各说一套。
        _note_error(errors, FilterErrorCode.TIME_UNUSABLE)
    matches = [
        _match_ref(index, record, rank, mappings.get(index))
        for (index, record), rank in zip(keep, ranks, strict=True)
    ]
    if any(_metadata_dropped(record) for _, record in keep):
        # 字段降级不拿掉命中本身，但「本层本该给这个值却没给」必须能被调用方看到。
        _note_error(errors, FilterErrorCode.RECORD_FIELD_OUT_OF_BOUNDS)
    return matches, _coverage(
        key, errors, quality, matched_total, len(keep), scanned,
        len(rows) - scanned, consumed_chars,
    )


def _coverage(
    key: str,
    errors: list[FilterErrorCode],
    quality: dict[str, int],
    matched_total: int,
    returned_total: int,
    scanned: int,
    skipped: int,
    scan_chars: int,
) -> SourceCoverage:
    """把一行覆盖结论收拢成一个出口：`partial` 与 `status` 只在这里推得，不留第二套判据。"""
    partial = bool(errors)
    if returned_total > 0:
        status = CoverageStatus.SEARCHED
    elif partial:
        status = CoverageStatus.INCOMPLETE
    else:
        status = CoverageStatus.NO_MATCH
    return SourceCoverage(
        source=key,
        status=status,
        matched_count=matched_total,
        returned_count=returned_total,
        records_scanned=scanned,
        skipped_count=skipped,
        scan_chars=scan_chars,
        partial=partial,
        filter_errors=tuple(errors),
        quality_issues=tuple(f"{code}={count}" for code, count in sorted(quality.items())),
        reason=_reason_text(errors),
    )


def _note_error(errors: list[FilterErrorCode], code: FilterErrorCode) -> None:
    """登记一个错误码（去重）；集合元素取自闭合枚举，长度天然有界，不另设封顶。"""
    if code not in errors:
        errors.append(code)


def _judge(
    index: int,
    record: StandardRecord,
    conditions: SourceFilter,
    mappings: dict[int, str],
    errors: list[FilterErrorCode],
) -> bool:
    """单条记录的过滤判定；被排除时按判据登记对应错误码（错误码是去重集合，计数见覆盖字段）。

    顺序固定：时间 → 项目归属 → 关键词。项目判定**只看映射表**：`record.project` 是 cwd，
    与策略项目名不是同一种值，既不做 `casefold` 相等也不拿 `quality.sourced` 当已核验。
    质量字段仍然参与判定（`UNVERIFIED_HEADER_CWD`/`UNKNOWN` 的记录就算给了映射也不可信），
    但它是必要条件而不是充分条件。
    """
    if conditions.time_restricted:
        # 界与记录时刻都已在入口/此处统一到 UTC，比较的是同一时刻且不再触发时区换算；
        # 区间左闭右开，缺一端就是开区间那一侧不判。
        moment = _record_moment(record)
        if moment is None:
            # 不猜、不回填时区、不用文件 mtime：无法比较就排除该条并使来源不完整。
            _note_error(errors, FilterErrorCode.TIME_UNUSABLE)
            return False
        lower = conditions.start
        upper = conditions.end
        if isinstance(lower, datetime) and moment < lower:
            return False
        if isinstance(upper, datetime) and moment >= upper:
            return False

    if not record.project_quality.sourced:
        _note_error(errors, FilterErrorCode.PROJECT_UNATTRIBUTED)
        return False
    mapped = mappings.get(index)
    if mapped is None:
        # 缺映射：判不出归属。既不能算命中，也不能当成「不属于本项目」而静静地排除。
        _note_error(errors, FilterErrorCode.PROJECT_UNATTRIBUTED)
        return False
    if conditions.project is not None and mapped != conditions.project:
        return False

    if conditions.keyword is not None:
        # `text` 的形状已在入口守住（`_record_shape_ok`），这里不再重复防御。
        return conditions.keyword in _key_of(record.text)
    return True


def _metadata_dropped(record: StandardRecord) -> bool:
    """该记录的某个短元数据**带着值但形状不合**（返回时会被降为 `null`）。

    `None` 是「本来就没有这个值」，不算降级；只有非空原值过不了 `_short_text` 判据时才是
    「本层拿不出这个字段」，需登记为覆盖不完整。
    """
    for value, limit in (
        (record.session_id, MAX_SESSION_ID_CHARS),
        (record.role, MAX_CALLER_KEY_CHARS),
        (record.executor, MAX_CALLER_KEY_CHARS),
    ):
        if value is not None and _short_text(value, limit) is None:
            return True
    return False


def _match_ref(
    index: int,
    record: StandardRecord,
    sequence: int | None,
    project: str | None,
) -> MatchRef:
    """把一条通过的记录变成对外引用：只带固定字段，不带正文。

    `project` 由调用方传入的**映射名**给出（未映射为 `None`）：本函数不读 `record.project`，
    以免把 cwd 当作项目标识外出。映射名已在入口过形态校验，这里不再二次判长。
    """
    reference: str | None = None
    if _location_form(record.location) is not None:
        reference = record.location.to_ref()
    moment = _record_moment(record)
    quality = record.time_quality
    if moment is None and quality is TimeQuality.EXACT:
        # 固定降级：拿不出时刻就不出示 exact（原值既不可比也没被规范化）；覆盖侧同一判据
        # 记 time_unusable，见 _filter_bucket。
        quality = TimeQuality.INVALID
    timestamp: str | None = moment.isoformat() if moment is not None else None
    return MatchRef(
        record_index=index,
        sequence=sequence,
        source=_source_key(record.source),
        session_id=_short_text(record.session_id, MAX_SESSION_ID_CHARS),
        role=_short_text(record.role, MAX_CALLER_KEY_CHARS),
        executor=_short_text(record.executor, MAX_CALLER_KEY_CHARS),
        timestamp=timestamp,
        time_quality=quality,
        project=project,
        project_quality=record.project_quality,
        location=reference,
    )


def _reason_text(errors: Sequence[FilterErrorCode]) -> str:
    """一句固定人话：只由固定片段拼成，不含正文、路径、关键词或任何原值。"""
    parts: list[str] = []
    if FilterErrorCode.SOURCE_NOT_SCANNED in errors:
        parts.append("本层未扫描该来源的任何记录（点名却无记录或预算已用尽），不得称无匹配")
    if FilterErrorCode.SCAN_RESOURCE_LIMIT in errors:
        parts.append("该来源自身扫描预算触限，未看完它的传入记录")
    if FilterErrorCode.GLOBAL_SCAN_LIMIT in errors:
        parts.append("全查询扫描预算用尽，本桶未扫完或一条也未扫")
    if FilterErrorCode.RESULT_TRUNCATED in errors:
        parts.append("该来源有匹配因全查询返回总上限未全部返回，返回的是结果子集")
    if FilterErrorCode.TIME_UNUSABLE in errors:
        parts.append("存在无法按时间过滤或无法规范化到 UTC 的记录")
    if FilterErrorCode.PROJECT_UNATTRIBUTED in errors:
        parts.append("存在缺少可用项目映射的记录")
    if FilterErrorCode.UNKNOWN_SOURCE in errors:
        parts.append("存在来源标识不受支持的记录，整桶未做匹配判定")
    if FilterErrorCode.PARSE_INCOMPLETE in errors:
        parts.append("解析侧登记了信息损失或归属不可核实的记录（含调用方申报的流级不完整）")
    if FilterErrorCode.LOCATION_UNREADABLE in errors:
        parts.append("存在位置不可解释的记录，名次与位置引用均不外出")
    if FilterErrorCode.RECORD_FIELD_OUT_OF_BOUNDS in errors:
        parts.append("存在短元数据形状不合只能降为 null 的命中项")
    if not parts:
        parts.append("已完整过滤该来源的传入记录")
    return "；".join(parts) + "。"
