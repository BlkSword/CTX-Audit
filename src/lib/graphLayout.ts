
import type { Node, Edge } from 'reactflow';

interface LayoutNode extends Node {
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
}

/**
 * Calculates a layout for the graph that separates connected components
 * and arranges them neatly.
 */
export function calculateGraphLayout(nodes: any[], edges: any[]): Node[] {
  const nodeMap = new Map<string, LayoutNode>();
  nodes.forEach(n => {
    nodeMap.set(n.id, { ...n, x: 0, y: 0, vx: 0, vy: 0 });
  });

  const adjacency = new Map<string, string[]>();
  edges.forEach(e => {
    if (!adjacency.has(e.source)) adjacency.set(e.source, []);
    if (!adjacency.has(e.target)) adjacency.set(e.target, []);
    adjacency.get(e.source)?.push(e.target);
    adjacency.get(e.target)?.push(e.source);
  });

  // Find connected components
  const visited = new Set<string>();
  const components: LayoutNode[][] = [];

  for (const node of nodes) {
    if (visited.has(node.id)) continue;

    const component: LayoutNode[] = [];
    const queue = [node.id];
    visited.add(node.id);

    while (queue.length > 0) {
      const currentId = queue.shift()!;
      const currentNode = nodeMap.get(currentId)!;
      component.push(currentNode);

      const neighbors = adjacency.get(currentId) || [];
      for (const neighborId of neighbors) {
        if (!visited.has(neighborId)) {
          visited.add(neighborId);
          queue.push(neighborId);
        }
      }
    }
    components.push(component);
  }

  // Layout each component
  let currentX = 0;
  let currentY = 0;
  const COMPONENT_PADDING = 300; // Space between components (reduced from 600)
  const MIN_NODE_SIZE = 150; // Minimum size for single-node components

  let rowMaxHeight = 0;

  // Sort components by size (larger first usually looks better or helps packing)
  components.sort((a, b) => b.length - a.length);

  const finalNodes: Node[] = [];

  for (const component of components) {
    // Run force simulation for this component
    runForceSimulation(component, edges);

    // Calculate component bounds
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    component.forEach(n => {
      minX = Math.min(minX, n.x!);
      minY = Math.min(minY, n.y!);
      maxX = Math.max(maxX, n.x!);
      maxY = Math.max(maxY, n.y!);
    });

    // Ensure minimum size for single-node components
    let width = maxX - minX;
    let height = maxY - minY;
    if (width < MIN_NODE_SIZE) width = MIN_NODE_SIZE;
    if (height < MIN_NODE_SIZE) height = MIN_NODE_SIZE;

    // Check if we need to wrap to next row
    // If currentX + width is too wide? Let's just do a simple flow layout.
    // We'll just place them left to right, if too wide, move down.
    if (currentX > 3000) { // Arbitrary width limit (increased since padding is reduced)
      currentX = 0;
      currentY += rowMaxHeight + COMPONENT_PADDING;
      rowMaxHeight = 0;
    }

    // Shift component to current position
    component.forEach(n => {
      n.position = {
        x: n.x! - minX + currentX,
        y: n.y! - minY + currentY
      };
      // Clean up temp props
      delete (n as any).x;
      delete (n as any).y;
      delete (n as any).vx;
      delete (n as any).vy;
      finalNodes.push(n);
    });

    currentX += width + COMPONENT_PADDING;
    rowMaxHeight = Math.max(rowMaxHeight, height);
  }

  return finalNodes;
}

/**
 * Assigns the best handles (top, bottom, left, right) for each edge based on relative node positions.
 */
export function assignEdgeHandles(nodes: Node[], edges: any[]): any[] {
  const nodeMap = new Map(nodes.map(n => [n.id, n]));

  return edges.map(edge => {
    const sourceNode = nodeMap.get(edge.source);
    const targetNode = nodeMap.get(edge.target);

    if (!sourceNode || !targetNode) return edge;

    const sx = sourceNode.position.x;
    const sy = sourceNode.position.y;
    const tx = targetNode.position.x;
    const ty = targetNode.position.y;

    const dx = tx - sx;
    const dy = ty - sy;

    let sourceHandle = 'bottom-src';
    let targetHandle = 'top';

    if (Math.abs(dx) > Math.abs(dy)) {
      // Horizontal connection
      if (dx > 0) {
        sourceHandle = 'right-src';
        targetHandle = 'left';
      } else {
        sourceHandle = 'left-src';
        targetHandle = 'right';
      }
    } else {
      // Vertical connection
      if (dy > 0) {
        sourceHandle = 'bottom-src';
        targetHandle = 'top';
      } else {
        sourceHandle = 'top-src';
        targetHandle = 'bottom';
      }
    }

    return {
      ...edge,
      sourceHandle,
      targetHandle,
    };
  });
}

function runForceSimulation(nodes: LayoutNode[], edges: Edge[]) {
  const iterations = 150;
  const springLength = 180;
  const k = 0.08; // Spring constant (reduced for gentler attraction)
  const c = 500; // Repulsion constant (increased to prevent overlap)

  // If no edges, use a circular layout for better distribution
  if (edges.length === 0) {
    const radius = Math.max(100, Math.sqrt(nodes.length) * 50);
    const angleStep = (2 * Math.PI) / nodes.length;

    nodes.forEach((n, i) => {
      n.x = Math.cos(i * angleStep) * radius + radius;
      n.y = Math.sin(i * angleStep) * radius + radius;
    });
    return;
  }

  // Initialize positions randomly if they are all 0
  nodes.forEach((n) => {
    n.x = Math.random() * 200;
    n.y = Math.random() * 200;
  });

  const nodeIndices = new Map(nodes.map((n, i) => [n.id, i]));
  const componentEdges = edges.filter(e => nodeIndices.has(e.source) && nodeIndices.has(e.target));

  for (let iter = 0; iter < iterations; iter++) {
    // Repulsion
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const n1 = nodes[i];
        const n2 = nodes[j];
        const dx = n1.x! - n2.x!;
        const dy = n1.y! - n2.y!;
        const distSq = dx * dx + dy * dy || 1;
        const dist = Math.sqrt(distSq);
        const force = c * c / distSq;

        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;

        n1.vx! += fx;
        n1.vy! += fy;
        n2.vx! -= fx;
        n2.vy! -= fy;
      }
    }

    // Attraction
    for (const edge of componentEdges) {
      const source = nodes[nodeIndices.get(edge.source)!];
      const target = nodes[nodeIndices.get(edge.target)!];

      const dx = target.x! - source.x!;
      const dy = target.y! - source.y!;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;

      const force = (dist - springLength) * k;

      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;

      source.vx! += fx;
      source.vy! += fy;
      target.vx! -= fx;
      target.vy! -= fy;
    }

    // Update positions
    for (const node of nodes) {
      // Damping with progressive cooling for better stabilization
      const coolingFactor = 1 - (iter / iterations);
      const damping = 0.3 + (coolingFactor * 0.3);
      node.vx! *= damping;
      node.vy! *= damping;

      node.x! += node.vx!;
      node.y! += node.vy!;
    }
  }
}
