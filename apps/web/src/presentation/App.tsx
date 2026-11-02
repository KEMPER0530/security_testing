import type { AuthSession } from "../application/auth";
import { Login } from "./Login";
import { useEffect, useMemo, useState, useRef } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import { createApi } from "@security-testing/api-client";
import { isActive, nextAction, stateLabel } from "../domain/workflow";
import { identity } from "../infrastructure/identity";
import { ScanProgress } from "./ScanProgress";
import { ScanFailure } from "./ScanFailure";
import { Findings } from "./Findings";
import { DiagnosticPlan } from "./DiagnosticPlan";
import { DiagnosticTypes } from "./DiagnosticTypes";
import {
  diagnosticProfiles,
  isProfile,
  profileOfJob,
  profileOfReport,
  type ProfileId,
} from "../domain/diagnostics";
import { AiAnalysisPending } from "./AttackAnalysis";
import "./style.css";
import {
  Routes,
  Route,
  Navigate,
  useLocation,
  useNavigate,
} from "react-router-dom";
import { Landing } from "./Landing";

type Item = Record<string, any>;
const registration = z.object({ url: z.url().max(2048) });
class RequestFailure extends Error {
  constructor(
    message: string,
    public status?: number,
  ) {
    super(message);
  }
}
function check(result: {
  data?: unknown;
  error?: any;
  response?: Response;
}): Item {
  if (result.error) {
    const status = result.response?.status;
    throw new RequestFailure(
      status === 401
        ? "ログインの有効期限が切れました。再ログインしてください。"
        : result.error?.error?.message ||
            "通信に失敗しました。接続を確認してもう一度お試しください。",
      status,
    );
  }
  return result.data as Item;
}
function stored(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}
function remember(key: string, value: string | null) {
  try {
    if (value) localStorage.setItem(key, value);
    else localStorage.removeItem(key);
  } catch {
    /* Storage can be unavailable in private mode. */
  }
}

function Workspace({ token, principal }: { token: string; principal: string }) {
  const client = useMemo(
    () =>
      createApi(import.meta.env.VITE_API_URL || "http://localhost:8000", token),
    [token],
  );
  const cache = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(() =>
    stored(`security-testing:${principal}:target`),
  );
  const [jobId, setJobId] = useState<string | null>(() =>
    stored(`security-testing:${principal}:job`),
  );
  const [profile, setProfile] = useState<ProfileId>(() => {
    const value = stored(`security-testing:${principal}:profile`);
    return isProfile(value) ? value : "web";
  });
  const profileInfo = diagnosticProfiles[profile];
  const [notice, setNotice] = useState("");
  const [problem, setProblem] = useState("");
  const [busyLabel, setBusyLabel] = useState("");
  const form = useForm<{ url: string }>({
    resolver: zodResolver(registration),
  });
  const targets = useQuery({
    queryKey: [principal, "targets"],
    queryFn: async () => {
      const items: Item[] = [];
      let offset: number | null = 0;
      do {
        const page = check(
          await client.GET("/v1/targets", {
            params: { query: { offset, limit: 100 } },
          }),
        );
        items.push(...page.items);
        offset = page.next_offset;
      } while (offset !== null);
      return { items, next_offset: null };
    },
  });
  const scans = useQuery({
    queryKey: [principal, "scans"],
    queryFn: async () => {
      const items: Item[] = [];
      let offset: number | null = 0;
      do {
        const page = check(
          await client.GET("/v1/scans", {
            params: { query: { offset, limit: 100 } },
          }),
        );
        items.push(...page.items);
        offset = page.next_offset;
      } while (offset !== null);
      return { items, next_offset: null };
    },
    refetchInterval: 5000,
  });
  const rows: Item[] = targets.data?.items || [];
  const jobs: Item[] = scans.data?.items || [];
  const selected = rows.find((t) => t.sk === selectedId) || null;
  const id = selected?.sk?.replace("TARGET#", "") || "";
  const activeSelectionRef = useRef({ profile, targetId: id });
  activeSelectionRef.current = { profile, targetId: id };
  const jobQuery = useQuery({
    queryKey: [principal, "job", jobId],
    queryFn: async () =>
      check(
        await client.GET("/v1/scans/{job_id}", {
          params: { path: { job_id: jobId! } },
        }),
      ),
    enabled: Boolean(jobId),
    refetchInterval: (q) => (isActive(q.state.data?.state) ? 2000 : false),
  });
  const candidateJob = jobQuery.data;
  const job =
    candidateJob &&
    profileOfJob(candidateJob) === profile &&
    candidateJob.target_id === id
      ? candidateJob
      : undefined;
  const reportQuery = useQuery({
    queryKey: [principal, "report", jobId],
    queryFn: async () =>
      check(
        await client.GET("/v1/scans/{job_id}/results", {
          params: { path: { job_id: jobId! } },
        }),
      ),
    enabled: Boolean(jobId && job?.state === "SUCCEEDED"),
    retry: 1,
  });
  const candidateReport = reportQuery.data;
  const reportMismatch = Boolean(
    candidateReport &&
    job &&
    (candidateReport.job_id !== job.id ||
      profileOfReport(candidateReport) !== profile),
  );
  const report = job && !reportMismatch ? candidateReport : undefined;
  const history = jobs.filter(
    (j) => profileOfJob(j) === profile && (!id || j.target_id === id),
  );
  const activeForTarget = jobs.find(
    (j) => j.target_id === id && isActive(j.state),
  );
  const running = Boolean(job && isActive(job.state));
  const run = useMutation({
    mutationFn: async ({ fn }: { fn: () => Promise<void>; label: string }) =>
      fn(),
    onMutate: ({ label }) => {
      setProblem("");
      setNotice("");
      setBusyLabel(label);
    },
    onError: (e) => setProblem(e.message),
    onSuccess: () => {
      void cache.invalidateQueries({ queryKey: [principal] });
    },
    onSettled: () => setBusyLabel(""),
  });
  const act = (label: string, fn: () => Promise<void>) =>
    run.mutate({ label, fn });
  useEffect(() => {
    remember(`security-testing:${principal}:target`, selectedId);
  }, [principal, selectedId]);
  useEffect(() => {
    remember(`security-testing:${principal}:job`, jobId);
  }, [principal, jobId]);
  useEffect(() => {
    remember(`security-testing:${principal}:profile`, profile);
  }, [principal, profile]);
  useEffect(() => {
    if (!rows.length) return;
    if (!rows.some((t) => t.sk === selectedId)) {
      const latest = [...rows].sort((a, b) =>
        b.created_at.localeCompare(a.created_at),
      )[0];
      setSelectedId(latest.sk);
    }
  }, [targets.data, selectedId]);
  useEffect(() => {
    if (jobId || !scans.data) return;
    const active = jobs.find(
      (j) =>
        isActive(j.state) &&
        profileOfJob(j) === profile &&
        (!selectedId || `TARGET#${j.target_id}` === selectedId),
    );
    if (active) {
      setJobId(active.id);
      setSelectedId(`TARGET#${active.target_id}`);
    }
  }, [scans.data, jobId, selectedId, profile]);
  useEffect(() => {
    if (!candidateJob || !id || !scans.data) return;
    if (
      candidateJob.target_id !== id ||
      profileOfJob(candidateJob) !== profile
    ) {
      setJobId(
        jobs.find((j) => j.target_id === id && profileOfJob(j) === profile)
          ?.id || null,
      );
    }
  }, [candidateJob, id, scans.data, profile]);
  useEffect(() => {
    if (
      jobQuery.error instanceof RequestFailure &&
      jobQuery.error.status === 404
    )
      setJobId(null);
  }, [jobQuery.error]);
  const chooseTarget = (target: Item) => {
    setSelectedId(target.sk);
    setProblem("");
    setNotice("");
    setJobId(
      jobs.find(
        (j) =>
          j.target_id === target.sk.replace("TARGET#", "") &&
          profileOfJob(j) === profile,
      )?.id || null,
    );
  };
  const chooseProfile = (value: ProfileId) => {
    setProfile(value);
    setProblem("");
    setNotice("");
    setJobId(
      jobs.find((j) => j.target_id === id && profileOfJob(j) === value)?.id ||
        null,
    );
  };
  const chooseHistory = (entry: Item) => {
    const value = profileOfJob(entry);
    if (!value) return;
    setProfile(value);
    setSelectedId(`TARGET#${entry.target_id}`);
    setJobId(entry.id);
  };
  const downloadPdf = (entry: Item) =>
    act("履歴のPDFを作成しています", async () => {
      const result = await client.GET("/v1/scans/{job_id}/report.pdf", {
        params: { path: { job_id: entry.id } },
        parseAs: "blob",
        headers: { Accept: "application/pdf" },
      });
      check(result);
      const url = URL.createObjectURL(result.data as Blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `security-testing-${entry.id}.pdf`;
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
      setNotice("選択した診断履歴のPDFをダウンロードしました。");
    });
  const deleteTarget = (target: Item) => {
    if (
      !window.confirm(
        `${target.url}\nこの診断対象と関連するすべての履歴を一覧から削除します。実行中の診断は停止します。よろしいですか？`,
      )
    )
      return;
    act("診断対象を削除しています", async () => {
      const targetId = target.sk.replace("TARGET#", "");
      check(
        await client.DELETE("/v1/targets/{target_id}", {
          params: { path: { target_id: targetId } },
        }),
      );
      cache.setQueryData([principal, "targets"], (old: Item | undefined) => ({
        ...old,
        items: (old?.items || []).filter((t: Item) => t.sk !== target.sk),
      }));
      cache.setQueryData([principal, "scans"], (old: Item | undefined) => ({
        ...old,
        items: (old?.items || []).filter((j: Item) => j.target_id !== targetId),
      }));
      if (selectedId === target.sk) {
        setSelectedId(null);
        setJobId(null);
      }
      cache.removeQueries({ queryKey: [principal, "report"] });
      setNotice("診断対象と関連する履歴を削除しました。");
    });
  };
  const deleteHistory = (entry: Item) => {
    if (
      !window.confirm(
        `${entry.url}\n${new Date(entry.created_at).toLocaleString("ja-JP")}\nこの診断履歴と結果へのアクセスを削除します。実行中の場合は停止します。よろしいですか？`,
      )
    )
      return;
    act("診断履歴を削除しています", async () => {
      check(
        await client.DELETE("/v1/scans/{job_id}", {
          params: { path: { job_id: entry.id } },
        }),
      );
      cache.setQueryData([principal, "scans"], (old: Item | undefined) => ({
        ...old,
        items: (old?.items || []).filter((j: Item) => j.id !== entry.id),
      }));
      if (jobId === entry.id) setJobId(null);
      cache.removeQueries({ queryKey: [principal, "report", entry.id] });
      setNotice("診断履歴を削除しました。診断対象は引き続き利用できます。");
    });
  };
  const jump = (section: string) =>
    document
      .getElementById(section)
      ?.scrollIntoView({ behavior: "smooth", block: "start" });
  const step = !selected ? 0 : job?.state === "SUCCEEDED" ? 2 : 1;
  const canStart = Boolean(
    id && !run.isPending && !activeForTarget && !running,
  );
  return (
    <>
      <header>
        <div>
          <div className="eyebrow">SITE SECURITY</div>
          <h1>診断ワークスペース</h1>
          <p>確認する。見つける。対策する。</p>
        </div>
        <button
          className="quiet logout"
          onClick={() => void identity.signoutRedirect()}
        >
          ログアウト
        </button>
      </header>
      <nav className="workflow" aria-label="診断の手順">
        {[
          ["targets", "対象登録"],
          ["scan", "診断開始"],
          ["results", "診断結果"],
        ].map(([section, label], index) => (
          <button
            key={section}
            className={
              index === step ? "current" : index < step ? "complete" : ""
            }
            aria-current={index === step ? "step" : undefined}
            onClick={() => jump(section)}
          >
            <span>{index < step ? "✓" : index + 1}</span>
            {label}
          </button>
        ))}
      </nav>
      <div className="stats">
        <article>
          <small>登録サイト</small>
          <strong>{rows.length}</strong>
        </article>
        <article>
          <small>実行中の診断</small>
          <strong>{jobs.filter((j) => isActive(j.state)).length}</strong>
        </article>
        <article>
          <small>完了した診断</small>
          <strong>{jobs.filter((j) => j.state === "SUCCEEDED").length}</strong>
        </article>
      </div>
      <div className="next-action">
        <span aria-hidden="true">→</span>
        <p>
          {running
            ? "診断を実行しています。下の進行状況に結果が自動表示されます。"
            : selected
              ? `${profileInfo.title}を選択中です。検査内容を確認して開始してください。`
              : nextAction(false)}
        </p>
      </div>
      {problem && (
        <div role="alert" className="notice error">
          {problem}
        </div>
      )}
      {notice && (
        <div role="status" className="notice success">
          {notice}
        </div>
      )}
      {busyLabel && (
        <div className="operation-status" role="status">
          <span className="spinner small" aria-hidden="true" />
          {busyLabel}
        </div>
      )}
      {targets.error && (
        <p role="alert" className="notice error">
          {targets.error.message}
          <button className="quiet" onClick={() => void targets.refetch()}>
            一覧を再取得
          </button>
        </p>
      )}
      <div>
        <section className="panel" id="targets">
          <div className="section-heading">
            <span className="step">01</span>
            <h2>診断対象</h2>
          </div>
          <form
            onSubmit={form.handleSubmit((value) =>
              act("サイトを登録しています", async () => {
                const target = check(
                  await client.POST("/v1/targets", { body: value }),
                );
                cache.setQueryData(
                  [principal, "targets"],
                  (old: Item | undefined) => ({
                    ...(old || { next_offset: null }),
                    items: [
                      ...(old?.items || []).filter(
                        (t: Item) => t.sk !== target.sk,
                      ),
                      target,
                    ],
                  }),
                );
                setSelectedId(target.sk);
                setJobId(null);
                form.reset();
                setNotice(
                  "サイトを登録しました。診断の種類を選んで開始してください。",
                );
              }),
            )}
          >
            <label htmlFor="target-url">診断する公開サイトのURL</label>
            <div className="input-row">
              <input
                id="target-url"
                type="url"
                inputMode="url"
                autoCapitalize="none"
                autoCorrect="off"
                placeholder="https://your-site.example/"
                {...form.register("url")}
              />
              <button disabled={run.isPending}>登録 ＋</button>
            </div>
            {form.formState.errors.url && (
              <p role="alert" className="field-error">
                https://から始まる有効なURLを入力してください。
              </p>
            )}
          </form>
          <p className="hint">
            対象を登録・選択し、下のカードから診断の種類を選んでください。
          </p>
          {targets.isPending ? (
            <div className="skeleton-list" aria-label="サイト一覧を読み込み中">
              <span />
              <span />
            </div>
          ) : (
            <div className="target-list">
              {rows.map((t) => (
                <div className="target-row" key={t.sk}>
                  <button
                    className={`target ${t.sk === selectedId ? "active" : ""}`}
                    data-target-id={t.sk}
                    aria-pressed={t.sk === selectedId}
                    onClick={() => chooseTarget(t)}
                  >
                    <span className="target-name">
                      <b>↗ {t.host}</b>
                      <small>{t.url}</small>
                    </span>
                    <span className="target-meta">
                      <span className="badge">診断対象</span>
                    </span>
                  </button>
                  <button
                    className="quiet danger"
                    aria-label="診断対象を削除"
                    title={t.url}
                    disabled={run.isPending}
                    onClick={() => deleteTarget(t)}
                  >
                    削除
                  </button>
                </div>
              ))}
              {!rows.length && (
                <p className="empty">最初のサイトを登録してください。</p>
              )}
            </div>
          )}
        </section>
      </div>
      <section className="panel" id="scan">
        <div className="section-heading">
          <span className="step">02</span>
          <h2>診断を開始</h2>
        </div>
        <p className="muted">
          調べたい内容に合わせて診断を選んでください。種類ごとに検査項目・結果・履歴が切り替わります。
        </p>
        <DiagnosticTypes
          selected={profile}
          onSelect={chooseProfile}
          historyCounts={Object.fromEntries(
            Object.keys(diagnosticProfiles).map((kind) => [
              kind,
              jobs.filter((j) => j.target_id === id && profileOfJob(j) === kind)
                .length,
            ]),
          )}
        />
        {history.length > 0 && (
          <button
            type="button"
            className="quiet"
            onClick={() => jump("results")}
          >
            {profileInfo.title}の結果・履歴を見る ↓
          </button>
        )}
        {!canStart && (
          <p
            className="hint prerequisite"
            data-testid="diagnostic-prerequisites"
          >
            {!selected
              ? "先に診断対象を選択してください。"
              : activeForTarget || running
                ? `${diagnosticProfiles[profileOfJob(activeForTarget) || profile].title}が進行中です。完了後に次の診断を開始できます。`
                : "操作の完了を待っています。"}
          </p>
        )}
        <DiagnosticPlan
          key={`${id}:${profile}`}
          client={client}
          profile={profile}
          principal={principal}
          targetId={id}
          targetUrl={selected?.url || ""}
          disabled={!canStart}
          onStarted={(j) => {
            void cache.invalidateQueries({ queryKey: [principal] });
            if (
              activeSelectionRef.current.profile === profileOfJob(j) &&
              activeSelectionRef.current.targetId === j.target_id
            ) {
              setJobId(j.id);
              jump("results");
            } else {
              setNotice(
                `${diagnosticProfiles[profileOfJob(j) || "web"].title}を受け付けました。該当する種類の履歴で確認できます。`,
              );
            }
          }}
        />
      </section>
      <section
        className="panel results-panel"
        id="results"
        data-job-id={jobId || ""}
      >
        <div className="section-heading">
          <span className="step">03</span>
          <h2>{profileInfo.title}の結果</h2>
          {job && (
            <span
              className={`badge ${job.state === "FAILED" ? "warning" : ""}`}
            >
              {stateLabel(job.state)}
            </span>
          )}
        </div>
        <p className="muted">
          {profileInfo.result}
          を表示します。現在選択している種類の診断結果だけを表示します。
        </p>
        {job && (
          <ScanProgress
            state={job.state}
            profileLabel={profileInfo.title}
            url={job.url}
            createdAt={job.created_at}
            loadingResults={job.state === "SUCCEEDED" && reportQuery.isPending}
          />
        )}
        {jobQuery.isPending && jobId && (
          <div className="operation-status" role="status">
            <span className="spinner small" aria-hidden="true" />
            診断の状態を読み込んでいます
          </div>
        )}
        {jobQuery.error && (
          <p className="notice error" role="alert">
            進行状況を取得できません。{jobQuery.error.message}
            <button className="quiet" onClick={() => void jobQuery.refetch()}>
              再取得
            </button>
          </p>
        )}
        {job?.error && (
          <ScanFailure message={job.error} code={job.error_code} />
        )}
        {running && (
          <button
            className="quiet cancel"
            disabled={run.isPending || job?.state === "CANCEL_REQUESTED"}
            onClick={() =>
              act("キャンセルを依頼しています", async () => {
                check(
                  await client.POST("/v1/scans/{job_id}/cancel", {
                    params: { path: { job_id: jobId! } },
                  }),
                );
                await jobQuery.refetch();
              })
            }
          >
            キャンセルを依頼
          </button>
        )}
        {reportQuery.error && (
          <div className="notice error" role="alert">
            結果を取得できません。{reportQuery.error.message}
            <button
              className="quiet"
              onClick={() => void reportQuery.refetch()}
            >
              結果を再取得
            </button>
          </div>
        )}
        {reportMismatch && (
          <p role="alert" className="notice error">
            診断種類または診断IDが一致しないため、この結果は表示できません。履歴から選び直してください。
          </p>
        )}
        {report && <Findings report={report} expectedProfile={profile} />}
        {!jobId && (
          <p className="empty">
            {profileInfo.title}
            の履歴はまだありません。この種類の診断を開始すると、進行状況と結果が表示されます。
          </p>
        )}
        <AiAnalysisPending />
        {history.length > 0 && (
          <details className="history-section" open>
            <summary>
              {profileInfo.title}の診断履歴 <span>{history.length}件</span>
            </summary>
            <div className="history">
              {history.map((j) => (
                <div className="history-row" key={j.id} data-history-id={j.id}>
                  <button
                    className={`history-item ${j.id === jobId ? "selected" : ""}`}
                    onClick={() => chooseHistory(j)}
                  >
                    <span
                      className={`history-dot ${isActive(j.state) ? "running" : j.state === "FAILED" ? "failed" : ""}`}
                    />
                    <span>
                      <b>{new URL(j.url).host}</b>
                      <small>
                        {diagnosticProfiles[profileOfJob(j) || "web"].title}
                      </small>
                      <small>
                        {new Date(j.created_at).toLocaleString("ja-JP")}
                      </small>
                    </span>
                    <span className="badge">{stateLabel(j.state)}</span>
                  </button>
                  <div className="history-actions">
                    <button
                      className="quiet pdf-button"
                      disabled={run.isPending || isActive(j.state)}
                      title={
                        isActive(j.state)
                          ? "診断終了後にダウンロードできます"
                          : "この診断履歴をPDFでダウンロード"
                      }
                      onClick={() => downloadPdf(j)}
                    >
                      PDF ↓
                    </button>
                    <button
                      className="quiet danger"
                      aria-label="診断履歴を削除"
                      disabled={run.isPending}
                      onClick={() => deleteHistory(j)}
                    >
                      削除
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </details>
        )}
      </section>
      <footer>
        SECURITY TESTING <span>観測した事実から、対策へ。</span>
      </footer>
    </>
  );
}
export function App() {
  const [user, setUser] = useState<AuthSession | null>(null);
  const [checking, setChecking] = useState(true);
  const [entering, setEntering] = useState(false);
  const [error, setError] = useState("");
  const location = useLocation();
  const navigate = useNavigate();
  const navigateRef = useRef(navigate);
  navigateRef.current = navigate;
  const initialPath = useRef(location.pathname).current;
  useEffect(() => {
    let live = true;
    const loaded = (u: AuthSession) => {
      if (live) setUser(u.expired ? null : u);
    };
    const expired = () => {
      if (live) setUser(null);
    };
    const unloaded = () => {
      if (live) {
        setUser(null);
        navigateRef.current("/", { replace: true });
      }
    };
    identity.events.addUserLoaded(loaded);
    identity.events.addUserUnloaded(unloaded);
    identity.events.addAccessTokenExpired(expired);
    void (async () => {
      try {
        const u =
          initialPath === "/callback" && !identity.password
            ? await identity.signinRedirectCallback()
            : await identity.getUser();
        if (!live) return;
        if (u && !u.expired) loaded(u);
        if (initialPath === "/callback")
          navigateRef.current(u && !u.expired ? "/dashboard" : "/login", {
            replace: true,
          });
      } catch {
        if (live)
          setError("ログイン状態を確認できません。もう一度お試しください。");
      } finally {
        if (live) setChecking(false);
      }
    })();
    return () => {
      live = false;
      identity.events.removeUserLoaded(loaded);
      identity.events.removeUserUnloaded(unloaded);
      identity.events.removeAccessTokenExpired(expired);
    };
  }, [initialPath]);

  async function enter() {
    if (entering || checking) return;
    setEntering(true);
    setError("");
    try {
      const current = await identity.getUser();
      if (current && !current.expired) {
        setUser(current);
        navigate("/dashboard");
      } else {
        setUser(null);
        if (identity.password) navigate("/login");
        else await identity.signinRedirect();
      }
    } catch {
      setError(
        "ログイン状態を確認できません。接続を確認してもう一度お試しください。",
      );
    } finally {
      setEntering(false);
    }
  }
  const loading = (
    <div className="auth-route-loading" role="status">
      ログイン状態を確認しています…
    </div>
  );
  const workspace =
    location.pathname === "/dashboard" && Boolean(user) && !checking;
  return (
    <div className={`shell ${workspace ? "" : "auth-shell"}`}>
      <aside>
        <a className="brand" href="/">
          ◈{" "}
          <span>
            SECURITY
            <br />
            TESTING
          </span>
        </a>
        <div className="nav-selected">◫ 診断ワークスペース</div>
      </aside>
      <main>
        <Routes>
          <Route
            path="/"
            element={
              <Landing
                onEnter={enter}
                busy={entering || checking}
                error={error}
                buttonLabel={
                  identity.password ? "ログイン" : "ログインして始める →"
                }
              />
            }
          />
          <Route
            path="/login"
            element={
              checking ? (
                loading
              ) : user ? (
                <Navigate to="/dashboard" replace />
              ) : identity.password ? (
                <Login auth={identity.password} />
              ) : (
                <Navigate to="/" replace />
              )
            }
          />
          <Route
            path="/dashboard"
            element={
              checking ? (
                loading
              ) : user ? (
                <Workspace
                  key={user.profile?.sub || "session"}
                  token={user.access_token}
                  principal={user.profile?.sub || "session"}
                />
              ) : (
                <Navigate to={identity.password ? "/login" : "/"} replace />
              )
            }
          />
          <Route
            path="/callback"
            element={
              checking ? (
                loading
              ) : (
                <Navigate to={user ? "/dashboard" : "/"} replace />
              )
            }
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}
