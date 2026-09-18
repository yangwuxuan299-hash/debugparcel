"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Eye, Plus, Redo2, RotateCcw, Trash2, Undo2 } from "lucide-react";

type Mask = { id: number; x: number; y: number; width: number; height: number };
type Point = { x: number; y: number };
type Gesture =
  | { type: "draw"; start: Point; id: number }
  | { type: "move"; start: Point; id: number; origin: Point }
  | null;

export function ScreenshotRedactor({
  file,
  onChange,
  onMaskCount,
}: {
  file: File;
  onChange: (blob: Blob | null) => void;
  onMaskCount: (count: number) => void;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const imageRef = useRef<HTMLImageElement | null>(null);
  const gestureRef = useRef<Gesture>(null);
  const beforeGestureRef = useRef<Mask[]>([]);
  const nextIdRef = useRef(1);
  const [masks, setMasks] = useState<Mask[]>([]);
  const [past, setPast] = useState<Mask[][]>([]);
  const [future, setFuture] = useState<Mask[][]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [ready, setReady] = useState(false);

  const render = useCallback((target: HTMLCanvasElement, showSelection: boolean) => {
    const image = imageRef.current;
    if (!image) return;
    target.width = image.naturalWidth;
    target.height = image.naturalHeight;
    const context = target.getContext("2d");
    if (!context) return;
    context.drawImage(image, 0, 0);
    for (const [index, mask] of masks.entries()) {
      context.fillStyle = "#071014";
      context.fillRect(mask.x, mask.y, mask.width, mask.height);
      if (showSelection && mask.id === selectedId) {
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
  }, [masks, selectedId]);

  useEffect(() => {
    const url = URL.createObjectURL(file);
    const image = new Image();
    image.onload = () => {
      imageRef.current = image;
      setMasks([]);
      setPast([]);
      setFuture([]);
      setSelectedId(null);
      setReady(true);
    };
    image.onerror = () => {
      setReady(false);
      onChange(null);
    };
    image.src = url;
    return () => URL.revokeObjectURL(url);
  }, [file, onChange]);

  useEffect(() => {
    if (canvasRef.current) render(canvasRef.current, true);
    onMaskCount(masks.length);
    if (!imageRef.current) {
      onChange(null);
      return;
    }
    const timeout = window.setTimeout(() => {
      const output = document.createElement("canvas");
      render(output, false);
      output.toBlob((blob) => onChange(blob), "image/png");
    }, 60);
    return () => window.clearTimeout(timeout);
  }, [masks, onChange, onMaskCount, ready, render, selectedId]);

  const commit = (next: Mask[]) => {
    setPast((items) => [...items.slice(-19), masks]);
    setMasks(next);
    setFuture([]);
  };

  const pointFromEvent = (event: React.PointerEvent<HTMLCanvasElement>): Point => {
    const canvas = event.currentTarget;
    const bounds = canvas.getBoundingClientRect();
    return {
      x: ((event.clientX - bounds.left) / bounds.width) * canvas.width,
      y: ((event.clientY - bounds.top) / bounds.height) * canvas.height,
    };
  };

  const handlePointerDown = (event: React.PointerEvent<HTMLCanvasElement>) => {
    const point = pointFromEvent(event);
    const hit = [...masks]
      .reverse()
      .find(
        (mask) =>
          point.x >= mask.x &&
          point.x <= mask.x + mask.width &&
          point.y >= mask.y &&
          point.y <= mask.y + mask.height,
      );
    beforeGestureRef.current = masks;
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
      setMasks([...masks, { id, x: point.x, y: point.y, width: 0, height: 0 }]);
    }
    event.currentTarget.setPointerCapture(event.pointerId);
  };

  const handlePointerMove = (event: React.PointerEvent<HTMLCanvasElement>) => {
    const gesture = gestureRef.current;
    if (!gesture) return;
    const point = pointFromEvent(event);
    const image = imageRef.current;
    if (!image) return;
    if (gesture.type === "draw") {
      const x = Math.max(0, Math.min(gesture.start.x, point.x));
      const y = Math.max(0, Math.min(gesture.start.y, point.y));
      const width = Math.min(image.naturalWidth - x, Math.abs(point.x - gesture.start.x));
      const height = Math.min(image.naturalHeight - y, Math.abs(point.y - gesture.start.y));
      setMasks((items) =>
        items.map((mask) => mask.id === gesture.id ? { ...mask, x, y, width, height } : mask),
      );
    } else {
      const active = masks.find((mask) => mask.id === gesture.id);
      if (!active) return;
      const x = Math.max(
        0,
        Math.min(image.naturalWidth - active.width, gesture.origin.x + point.x - gesture.start.x),
      );
      const y = Math.max(
        0,
        Math.min(image.naturalHeight - active.height, gesture.origin.y + point.y - gesture.start.y),
      );
      setMasks((items) =>
        items.map((mask) => mask.id === gesture.id ? { ...mask, x, y } : mask),
      );
    }
  };

  const handlePointerUp = (event: React.PointerEvent<HTMLCanvasElement>) => {
    const gesture = gestureRef.current;
    if (!gesture) return;
    gestureRef.current = null;
    const next = masks.filter((mask) => mask.width >= 4 && mask.height >= 4);
    setPast((items) => [...items.slice(-19), beforeGestureRef.current]);
    setMasks(next);
    setFuture([]);
    event.currentTarget.releasePointerCapture(event.pointerId);
  };

  const addMask = () => {
    const image = imageRef.current;
    if (!image) return;
    const id = nextIdRef.current++;
    const width = image.naturalWidth * 0.28;
    const height = Math.max(34, image.naturalHeight * 0.08);
    const next = [
      ...masks,
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
    canvasRef.current?.focus();
  };

  const removeSelected = () => {
    if (selectedId === null) return;
    commit(masks.filter((mask) => mask.id !== selectedId));
    setSelectedId(null);
  };

  const undo = () => {
    const previous = past.at(-1);
    if (!previous) return;
    setFuture((items) => [masks, ...items].slice(0, 20));
    setPast((items) => items.slice(0, -1));
    setMasks(previous);
    setSelectedId(null);
  };

  const redo = () => {
    const next = future[0];
    if (!next) return;
    setPast((items) => [...items, masks].slice(-20));
    setFuture((items) => items.slice(1));
    setMasks(next);
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
    const next = masks.map((mask) => {
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

  if (!ready) {
    return (
      <div className="grid min-h-72 place-items-center rounded-2xl border border-[var(--line)] bg-[var(--soft)] text-sm text-[var(--muted-strong)]">
        Loading screenshot…
      </div>
    );
  }

  return (
    <div>
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
        <span className="ml-auto inline-flex items-center gap-1.5 font-mono text-xs text-[var(--muted-strong)]">
          <Eye size={14} /> {masks.length} mask{masks.length === 1 ? "" : "s"}
        </span>
      </div>
      <div className="canvas-shell">
        <canvas
          ref={canvasRef}
          className="block h-auto max-h-[64vh] w-full cursor-crosshair object-contain"
          tabIndex={0}
          aria-label="Screenshot mask editor. Drag to add a mask. Select a mask and use arrow keys to move it, Shift plus arrow keys to resize, or Delete to remove."
          onPointerDown={handlePointerDown}
          onPointerMove={handlePointerMove}
          onPointerUp={handlePointerUp}
          onKeyDown={handleKeyDown}
        />
      </div>
      <p className="mt-3 flex items-start gap-2 text-sm leading-6 text-[var(--muted-strong)]">
        <RotateCcw className="mt-1 shrink-0" size={14} />
        Drag over names, avatars, notifications, QR codes, or session IDs. Masks are burned into the exported pixels.
      </p>
    </div>
  );
}
