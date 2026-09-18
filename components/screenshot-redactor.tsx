"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { CircleAlert, Eye, Plus, Redo2, RotateCcw, Trash2, Undo2 } from "lucide-react";

type Mask = { id: number; x: number; y: number; width: number; height: number };
type Point = { x: number; y: number };
type Gesture =
  | { type: "draw"; start: Point; id: number }
  | { type: "move"; start: Point; id: number; origin: Point }
  | null;
type LoadStatus = "loading" | "ready" | "error";

const MAX_IMAGE_PIXELS = 32_000_000;
const MAX_IMAGE_EDGE = 16_384;

export function ScreenshotRedactor({
  file,
  onChange,
  onMaskCount,
  onError,
}: {
  file: File;
  onChange: (blob: Blob | null) => void;
  onMaskCount: (count: number) => void;
  onError?: (message: string) => void;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const outputCanvasRef = useRef<HTMLCanvasElement | null>(null);
  const imageRef = useRef<HTMLImageElement | null>(null);
  const masksRef = useRef<Mask[]>([]);
  const gestureRef = useRef<Gesture>(null);
  const beforeGestureRef = useRef<Mask[]>([]);
  const nextIdRef = useRef(1);
  const exportGenerationRef = useRef(0);
  const [masks, setMasks] = useState<Mask[]>([]);
  const [committedMasks, setCommittedMasks] = useState<Mask[]>([]);
  const [past, setPast] = useState<Mask[][]>([]);
  const [future, setFuture] = useState<Mask[][]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [status, setStatus] = useState<LoadStatus>("loading");
  const [loadError, setLoadError] = useState("");

  const updateMasks = useCallback((next: Mask[]) => {
    masksRef.current = next;
    setMasks(next);
  }, []);

  const draw = useCallback((
    target: HTMLCanvasElement,
    items: Mask[],
    activeId: number | null,
    showSelection: boolean,
  ) => {
    const image = imageRef.current;
    if (!image) return;
    const context = target.getContext("2d");
    if (!context) return;
    context.clearRect(0, 0, target.width, target.height);
    context.drawImage(image, 0, 0);
    for (const [index, mask] of items.entries()) {
      context.fillStyle = "#071014";
      context.fillRect(mask.x, mask.y, mask.width, mask.height);
      if (showSelection && mask.id === activeId) {
        context.strokeStyle = "#b8f36b";
        context.lineWidth = Math.max(2, image.naturalWidth / 500);
        context.strokeRect(mask.x, mask.y, mask.width, mask.height);
      }
      if (showSelection) {
        const labelSize = Math.max(14, image.naturalWidth / 70);
        context.fillStyle = "#b8f36b";
        context.fillRect(mask.x, mask.y, labelSize * 1.7, labelSize * 1.4);
        context.fillStyle = "#071014";
        context.font = `700 ${labelSize}px sans-serif`;
        context.textBaseline = "top";
        context.fillText(String(index + 1), mask.x + labelSize * 0.45, mask.y + labelSize * 0.12);
      }
    }
  }, []);

  useEffect(() => {
    let disposed = false;
    const url = URL.createObjectURL(file);
    const image = new Image();

    const fail = (message: string) => {
      if (disposed) return;
      imageRef.current = null;
      outputCanvasRef.current = null;
      updateMasks([]);
      setCommittedMasks([]);
      setPast([]);
      setFuture([]);
      setSelectedId(null);
      setLoadError(message);
      setStatus("error");
      onMaskCount(0);
      onChange(null);
      onError?.(message);
    };

    window.queueMicrotask(() => {
      if (disposed) return;
      setStatus("loading");
      setLoadError("");
    });
    imageRef.current = null;
    gestureRef.current = null;
    exportGenerationRef.current += 1;
    onChange(null);

    image.onload = () => {
      if (disposed) return;
      const { naturalWidth: width, naturalHeight: height } = image;
      if (!width || !height) {
        fail("This screenshot has no readable pixel dimensions. Choose a valid PNG, JPG, or WebP image.");
        return;
      }
      if (width > MAX_IMAGE_EDGE || height > MAX_IMAGE_EDGE) {
        fail(`This screenshot is ${width} × ${height}px. Each edge must be ${MAX_IMAGE_EDGE.toLocaleString()}px or smaller.`);
        return;
      }
      if (width * height > MAX_IMAGE_PIXELS) {
        fail(`This screenshot contains ${(width * height / 1_000_000).toFixed(1)} megapixels. The limit is 32 megapixels.`);
        return;
      }

      const preview = canvasRef.current;
      if (!preview) {
        fail("The screenshot editor could not be initialized. Return to the previous step and try again.");
        return;
      }

      imageRef.current = image;
      preview.width = width;
      preview.height = height;
      const output = document.createElement("canvas");
      output.width = width;
      output.height = height;
      outputCanvasRef.current = output;
      nextIdRef.current = 1;
      updateMasks([]);
      setCommittedMasks([]);
      setPast([]);
      setFuture([]);
      setSelectedId(null);
      setLoadError("");
      setStatus("ready");
    };
    image.onerror = () => {
      fail("This screenshot could not be decoded. Choose a valid PNG, JPG, or WebP image and try again.");
    };
    image.src = url;

    return () => {
      disposed = true;
      URL.revokeObjectURL(url);
    };
  }, [file, onChange, onError, onMaskCount, updateMasks]);

  useEffect(() => {
    if (status !== "ready" || !canvasRef.current) return;
    draw(canvasRef.current, masks, selectedId, true);
    onMaskCount(masks.length);
  }, [draw, masks, onMaskCount, selectedId, status]);

  useEffect(() => {
    if (status !== "ready") return;
    const output = outputCanvasRef.current;
    if (!output || !imageRef.current) {
      onChange(null);
      return;
    }

    onChange(null);
    const generation = ++exportGenerationRef.current;
    draw(output, committedMasks, null, false);
    const reportEncodingFailure = () => {
      if (generation !== exportGenerationRef.current) return;
      const message = "The redacted screenshot could not be encoded as PNG. Try a smaller image.";
      setLoadError(message);
      setStatus("error");
      onChange(null);
      onError?.(message);
    };
    try {
      output.toBlob((blob) => {
        if (generation !== exportGenerationRef.current) return;
        if (blob) {
          onChange(blob);
          return;
        }
        reportEncodingFailure();
      }, "image/png");
    } catch {
      reportEncodingFailure();
    }
    return () => {
      if (generation === exportGenerationRef.current) exportGenerationRef.current += 1;
    };
  }, [committedMasks, draw, onChange, onError, status]);

  const commit = useCallback((next: Mask[]) => {
    const current = masksRef.current;
    setPast((items) => [...items.slice(-19), current]);
    updateMasks(next);
    setCommittedMasks(next);
    setFuture([]);
  }, [updateMasks]);

  const pointFromEvent = (event: React.PointerEvent<HTMLCanvasElement>): Point => {
    const canvas = event.currentTarget;
    const bounds = canvas.getBoundingClientRect();
    return {
      x: ((event.clientX - bounds.left) / bounds.width) * canvas.width,
      y: ((event.clientY - bounds.top) / bounds.height) * canvas.height,
    };
  };

  const handlePointerDown = (event: React.PointerEvent<HTMLCanvasElement>) => {
    if (status !== "ready") return;
    event.preventDefault();
    event.currentTarget.focus({ preventScroll: true });
    const point = pointFromEvent(event);
    const current = masksRef.current;
    const hit = [...current]
      .reverse()
      .find(
        (mask) =>
          point.x >= mask.x &&
          point.x <= mask.x + mask.width &&
          point.y >= mask.y &&
          point.y <= mask.y + mask.height,
      );
    beforeGestureRef.current = current;
    if (hit) {
      setSelectedId(hit.id);
      gestureRef.current = {
        type: "move",
        start: point,
        id: hit.id,
        origin: { x: hit.x, y: hit.y },
      };
    } else {
      const id = nextIdRef.current++;
      setSelectedId(id);
      gestureRef.current = { type: "draw", start: point, id };
      updateMasks([...current, { id, x: point.x, y: point.y, width: 0, height: 0 }]);
    }
    event.currentTarget.setPointerCapture(event.pointerId);
  };

  const handlePointerMove = (event: React.PointerEvent<HTMLCanvasElement>) => {
    const gesture = gestureRef.current;
    if (!gesture) return;
    event.preventDefault();
    const point = pointFromEvent(event);
    const image = imageRef.current;
    if (!image) return;
    const current = masksRef.current;
    if (gesture.type === "draw") {
      const x = Math.max(0, Math.min(gesture.start.x, point.x));
      const y = Math.max(0, Math.min(gesture.start.y, point.y));
      const width = Math.min(image.naturalWidth - x, Math.abs(point.x - gesture.start.x));
      const height = Math.min(image.naturalHeight - y, Math.abs(point.y - gesture.start.y));
      updateMasks(current.map((mask) => mask.id === gesture.id ? { ...mask, x, y, width, height } : mask));
    } else {
      const active = current.find((mask) => mask.id === gesture.id);
      if (!active) return;
      const x = Math.max(
        0,
        Math.min(image.naturalWidth - active.width, gesture.origin.x + point.x - gesture.start.x),
      );
      const y = Math.max(
        0,
        Math.min(image.naturalHeight - active.height, gesture.origin.y + point.y - gesture.start.y),
      );
      updateMasks(current.map((mask) => mask.id === gesture.id ? { ...mask, x, y } : mask));
    }
  };

  const finishGesture = (event?: React.PointerEvent<HTMLCanvasElement>) => {
    if (!gestureRef.current) return;
    gestureRef.current = null;
    const next = masksRef.current.filter((mask) => mask.width >= 4 && mask.height >= 4);
    setPast((items) => [...items.slice(-19), beforeGestureRef.current]);
    updateMasks(next);
    setCommittedMasks(next);
    setFuture([]);
    if (event?.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  };

  const cancelGesture = (event: React.PointerEvent<HTMLCanvasElement>) => {
    if (!gestureRef.current) return;
    gestureRef.current = null;
    updateMasks(beforeGestureRef.current);
    setCommittedMasks(beforeGestureRef.current);
    setSelectedId(null);
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  };

  const addMask = () => {
    const image = imageRef.current;
    if (!image) return;
    const id = nextIdRef.current++;
    const width = Math.min(image.naturalWidth, Math.max(6, image.naturalWidth * 0.28));
    const height = Math.min(image.naturalHeight, Math.max(6, image.naturalHeight * 0.08));
    const next = [
      ...masksRef.current,
      {
        id,
        x: (image.naturalWidth - width) / 2,
        y: (image.naturalHeight - height) / 2,
        width,
        height,
      },
    ];
    commit(next);
    setSelectedId(id);
    canvasRef.current?.focus({ preventScroll: true });
  };

  const removeSelected = () => {
    if (selectedId === null) return;
    commit(masksRef.current.filter((mask) => mask.id !== selectedId));
    setSelectedId(null);
  };

  const undo = () => {
    const previous = past.at(-1);
    if (!previous) return;
    setFuture((items) => [masksRef.current, ...items].slice(0, 20));
    setPast((items) => items.slice(0, -1));
    updateMasks(previous);
    setCommittedMasks(previous);
    setSelectedId(null);
  };

  const redo = () => {
    const next = future[0];
    if (!next) return;
    setPast((items) => [...items, masksRef.current].slice(-20));
    setFuture((items) => items.slice(1));
    updateMasks(next);
    setCommittedMasks(next);
    setSelectedId(null);
  };

  const handleKeyDown = (event: React.KeyboardEvent<HTMLCanvasElement>) => {
    if (event.key === "Delete" || event.key === "Backspace") {
      event.preventDefault();
      removeSelected();
      return;
    }
    if (event.key === "Escape") {
      setSelectedId(null);
      return;
    }
    if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(event.key) || selectedId === null) {
      return;
    }
    event.preventDefault();
    const amount = event.altKey ? 10 : 2;
    const dx = event.key === "ArrowLeft" ? -amount : event.key === "ArrowRight" ? amount : 0;
    const dy = event.key === "ArrowUp" ? -amount : event.key === "ArrowDown" ? amount : 0;
    const image = imageRef.current;
    if (!image) return;
    const next = masksRef.current.map((mask) => {
      if (mask.id !== selectedId) return mask;
      if (event.shiftKey) {
        return {
          ...mask,
          width: Math.max(6, Math.min(image.naturalWidth - mask.x, mask.width + dx)),
          height: Math.max(6, Math.min(image.naturalHeight - mask.y, mask.height + dy)),
        };
      }
      return {
        ...mask,
        x: Math.max(0, Math.min(image.naturalWidth - mask.width, mask.x + dx)),
        y: Math.max(0, Math.min(image.naturalHeight - mask.height, mask.y + dy)),
      };
    });
    commit(next);
  };

  const selectMask = (id: number) => {
    setSelectedId(id);
    window.requestAnimationFrame(() => canvasRef.current?.focus({ preventScroll: true }));
  };

  return (
    <div>
      {status === "loading" && (
        <div role="status" aria-live="polite" className="grid min-h-72 place-items-center rounded-2xl border border-[var(--line)] bg-[var(--soft)] px-6 text-center text-sm text-[var(--muted-strong)]">
          Loading screenshot…
        </div>
      )}

      {status === "error" && (
        <div className="grid min-h-72 place-items-center rounded-2xl border border-[#e0a6a1] bg-[#fff1ef] px-6 py-10 text-center text-[#7c2520]">
          <div className="max-w-lg">
            <CircleAlert className="mx-auto" size={28} />
            <p className="mt-3 font-semibold">Screenshot unavailable</p>
            <p className="mt-2 text-sm leading-6">{loadError}</p>
            <p className="mt-2 text-xs leading-5 opacity-80">Return to the previous step to replace this file.</p>
          </div>
        </div>
      )}

      <div className={status === "ready" ? "" : "hidden"} aria-hidden={status !== "ready"}>
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <button className="tool-button" type="button" onClick={addMask}>
            <Plus size={15} /> Add mask
          </button>
          <button className="tool-button" type="button" onClick={undo} disabled={!past.length}>
            <Undo2 size={15} /> Undo
          </button>
          <button className="tool-button" type="button" onClick={redo} disabled={!future.length}>
            <Redo2 size={15} /> Redo
          </button>
          <button className="tool-button" type="button" onClick={removeSelected} disabled={selectedId === null}>
            <Trash2 size={15} /> Delete
          </button>
          <span className="ml-auto inline-flex items-center gap-1.5 font-mono text-xs text-[var(--muted-strong)]" aria-live="polite">
            <Eye size={14} /> {masks.length} mask{masks.length === 1 ? "" : "s"}
          </span>
        </div>

        {masks.length > 0 && (
          <div className="mask-list mb-3" role="group" aria-label="Screenshot masks">
            {masks.map((mask, index) => (
              <button
                key={mask.id}
                type="button"
                className="mask-selector"
                aria-pressed={mask.id === selectedId}
                aria-label={`Select mask ${index + 1}, ${Math.round(mask.width)} by ${Math.round(mask.height)} pixels`}
                onClick={() => selectMask(mask.id)}
              >
                <span>Mask {index + 1}</span>
                <span className="font-mono text-[11px] opacity-70">{Math.round(mask.width)} × {Math.round(mask.height)} px</span>
              </button>
            ))}
          </div>
        )}

        <div className="canvas-shell">
          <canvas
            ref={canvasRef}
            className="redactor-canvas block h-auto max-h-[64vh] w-auto max-w-full cursor-crosshair"
            tabIndex={0}
            aria-label="Screenshot mask editor"
            aria-describedby="mask-editor-help"
            onPointerDown={handlePointerDown}
            onPointerMove={handlePointerMove}
            onPointerUp={finishGesture}
            onPointerCancel={cancelGesture}
            onLostPointerCapture={cancelGesture}
            onKeyDown={handleKeyDown}
          />
        </div>
        <p id="mask-editor-help" className="mt-3 flex items-start gap-2 text-sm leading-6 text-[var(--muted-strong)]">
          <RotateCcw className="mt-1 shrink-0" size={14} />
          Drag over sensitive content. Choose a mask from the list, then use arrow keys to move it, Shift plus arrow keys to resize, or Delete to remove it. Masks are burned into exported pixels.
        </p>
      </div>
    </div>
  );
}
