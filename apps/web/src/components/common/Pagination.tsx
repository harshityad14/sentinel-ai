import React from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";

interface PaginationProps {
  total: number;
  limit: number;
  offset: number;
  onPageChange: (newOffset: number) => void;
}

export const Pagination: React.FC<PaginationProps> = ({
  total = 0,
  limit = 50,
  offset = 0,
  onPageChange,
}) => {
  const safeLimit = limit > 0 ? limit : 50;
  const safeOffset = offset >= 0 ? offset : 0;
  const currentPage = Math.floor(safeOffset / safeLimit) + 1;
  const totalPages = Math.max(1, Math.ceil(total / safeLimit));

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0.75rem 1rem",
        borderTop: "1px solid var(--border-subtle)",
        fontSize: "0.85rem",
        color: "var(--text-secondary)",
      }}
    >
      <div>
        Showing <span style={{ color: "var(--text-primary)", fontWeight: 500 }}>{total > 0 ? offset + 1 : 0}</span> to{" "}
        <span style={{ color: "var(--text-primary)", fontWeight: 500 }}>
          {Math.min(offset + limit, total)}
        </span>{" "}
        of <span style={{ color: "var(--text-primary)", fontWeight: 500 }}>{total}</span> entries
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
        <button
          className="btn btn-secondary btn-sm"
          disabled={offset <= 0}
          onClick={() => onPageChange(Math.max(0, offset - limit))}
          aria-label="Previous page"
        >
          <ChevronLeft size={16} /> Prev
        </button>
        <span style={{ padding: "0 0.5rem", fontWeight: 500 }}>
          Page {currentPage} of {totalPages}
        </span>
        <button
          className="btn btn-secondary btn-sm"
          disabled={offset + limit >= total}
          onClick={() => onPageChange(offset + limit)}
          aria-label="Next page"
        >
          Next <ChevronRight size={16} />
        </button>
      </div>
    </div>
  );
};
