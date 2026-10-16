import micromorph from "micromorph"
import { FullSlug, RelativeURL, getFullSlug, normalizeRelativeURLs } from "../../util/path"
import { fetchCanonical } from "./util"

// adapted from `micromorph`
// https://github.com/natemoo-re/micromorph
const NODE_TYPE_ELEMENT = 1
let announcer = document.createElement("route-announcer")
const isElement = (target: EventTarget | null): target is Element =>
  (target as Node)?.nodeType === NODE_TYPE_ELEMENT
const isLocalUrl = (href: string) => {
  try {
    const url = new URL(href)
    if (window.location.origin === url.origin) {
      return true
    }
  } catch (e) {}
  return false
}

const isSamePage = (url: URL): boolean => {
  const sameOrigin = url.origin === window.location.origin
  const samePath = url.pathname === window.location.pathname
  return sameOrigin && samePath
}

const getOpts = ({ target }: Event): { url: URL; scroll?: boolean } | undefined => {
  if (!isElement(target)) return
  if (target.attributes.getNamedItem("target")?.value === "_blank") return
  const a = target.closest("a")
  if (!a) return
  if ("routerIgnore" in a.dataset) return
  const { href } = a
  if (!isLocalUrl(href)) return
  return { url: new URL(href), scroll: "routerNoscroll" in a.dataset ? false : undefined }
}

function notifyNav(url: FullSlug) {
  const event: CustomEventMap["nav"] = new CustomEvent("nav", { detail: { url } })
  document.dispatchEvent(event)
}

const cleanupFns: Set<(...args: any[]) => void> = new Set()
window.addCleanup = (fn) => cleanupFns.add(fn)

function startLoading() {
  document.querySelector(".navigation-progress")?.remove()
  const loadingBar = document.createElement("div")
  loadingBar.className = "navigation-progress"
  loadingBar.style.width = "0"
  document.body.prepend(loadingBar)

  setTimeout(() => {
    loadingBar.style.width = "80%"
  }, 100)
}

function stopLoading() {
  const loadingBar = document.querySelector(".navigation-progress")
  if (loadingBar) {
    loadingBar.remove()
  }
}

let isNavigating = false
let p: DOMParser
async function _navigate(url: URL, isBack: boolean = false) {
  isNavigating = true
  startLoading()
  p = p || new DOMParser()
  const contents = await fetchCanonical(url)
    .then((res) => {
      const contentType = res.headers.get("content-type")
      if (contentType?.startsWith("text/html")) {
        return res.text()
      } else {
        window.location.assign(url)
      }
    })
    .catch(() => {
      window.location.assign(url)
    })

  if (!contents) return

  // notify about to nav
  const event: CustomEventMap["prenav"] = new CustomEvent("prenav", { detail: {} })
  document.dispatchEvent(event)

  // cleanup old
  cleanupFns.forEach((fn) => fn())
  cleanupFns.clear()

  const html = p.parseFromString(contents, "text/html")
  normalizeRelativeURLs(html, url)

  let title = html.querySelector("title")?.textContent
  if (title) {
    document.title = title
  } else {
    const h1 = document.querySelector("h1")
    title = h1?.innerText ?? h1?.textContent ?? url.pathname
  }
  if (announcer.textContent !== title) {
    announcer.textContent = title
  }
  announcer.dataset.persist = ""
  html.body.appendChild(announcer)

  document.querySelector(".navigation-progress")?.remove()
  micromorph(document.body, html.body)

  // scroll into place and add history
  if (!isBack) {
    if (url.hash) {
      const el = document.getElementById(decodeURIComponent(url.hash.substring(1)))
      el?.scrollIntoView()
    } else {
      window.scrollTo({ top: 0 })
    }
  }

  // now, patch head, re-executing scripts
  const elementsToRemove = document.head.querySelectorAll(":not([data-persist])")
  elementsToRemove.forEach((el) => el.remove())
  const elementsToAdd = html.head.querySelectorAll(":not([data-persist])")
  elementsToAdd.forEach((el) => document.head.appendChild(el))

  // delay setting the url until now
  // at this point everything is loaded so changing the url should resolve to the correct addresses
  if (!isBack) {
    history.pushState({}, "", url)
  }

  notifyNav(getFullSlug(window))
  delete announcer.dataset.persist
}

async function navigate(url: URL, isBack: boolean = false) {
  if (isNavigating) return
  isNavigating = true
  try {
    await _navigate(url, isBack)
  } catch (e) {
    console.error(e)
    window.location.assign(url)
  } finally {
    stopLoading()
    isNavigating = false
  }
}

window.spaNavigate = navigate

function createRouter() {
  if (typeof window !== "undefined") {
    window.addEventListener("click", async (event) => {
      const { url } = getOpts(event) ?? {}
      // dont hijack behaviour, just let browser act normally
      if (!url || event.ctrlKey || event.metaKey) return
      event.preventDefault()

      if (isSamePage(url) && url.hash) {
        const el = document.getElementById(decodeURIComponent(url.hash.substring(1)))
        el?.scrollIntoView()
        history.pushState({}, "", url)
        return
      }

      navigate(url, false)
    })

    window.addEventListener("popstate", (event) => {
      const { url } = getOpts(event) ?? {}
      if (window.location.hash && window.location.pathname === url?.pathname) return
      navigate(new URL(window.location.toString()), true)
      return
    })
  }

  return new (class Router {
    go(pathname: RelativeURL) {
      const url = new URL(pathname, window.location.toString())
      return navigate(url, false)
    }

    back() {
      return window.history.back()
    }

    forward() {
      return window.history.forward()
    }
  })()
}

createRouter()
notifyNav(getFullSlug(window))

if (!customElements.get("route-announcer")) {
  const attrs = {
    "aria-live": "assertive",
    "aria-atomic": "true",
    style:
      "position: absolute; left: 0; top: 0; clip: rect(0 0 0 0); clip-path: inset(50%); overflow: hidden; white-space: nowrap; width: 1px; height: 1px",
  }

  customElements.define(
    "route-announcer",
    class RouteAnnouncer extends HTMLElement {
      constructor() {
        super()
      }
      connectedCallback() {
        for (const [key, value] of Object.entries(attrs)) {
          this.setAttribute(key, value)
        }
      }
    },
  )
}

// ========================================================
// 极客高阶 · 真 3D 交互知识拓扑宇宙引擎 (Three.js WebGL 3D Architecture)
// ========================================================

let graph3DRunning = false
let graph3DAnimId: number | null = null

function checkAndInit3DGraph() {
  const isLanding =
    document.body.dataset.slug === "index" ||
    window.location.pathname === "/" ||
    window.location.pathname === "/index" ||
    document.querySelector(".landing-hud") !== null

  const existingCanvas = document.getElementById("quartz-3d-graph-canvas")

  if (!isLanding) {
    if (existingCanvas) {
      existingCanvas.style.display = "none"
    }
    if (graph3DAnimId !== null) {
      cancelAnimationFrame(graph3DAnimId)
      graph3DAnimId = null
    }
    graph3DRunning = false
    const tt = document.getElementById("quartz-3d-tooltip")
    if (tt) tt.className = ""
    return
  }

  if (existingCanvas) {
    existingCanvas.style.display = "block"
    return
  }

  // Ensure THREE is loaded
  if (typeof (window as any).THREE === "undefined") {
    const s = document.createElement("script")
    s.src = "/static/three.min.js"
    s.onload = () => init3DUniverse()
    document.head.appendChild(s)
  } else {
    init3DUniverse()
  }
}

function init3DUniverse() {
  const THREE = (window as any).THREE
  if (!THREE || document.getElementById("quartz-3d-graph-canvas")) return

  const canvas = document.createElement("canvas")
  canvas.id = "quartz-3d-graph-canvas"
  canvas.className = "quartz-3d-canvas"
  canvas.setAttribute("data-persist", "true")
  document.body.prepend(canvas)

  let tooltip = document.getElementById("quartz-3d-tooltip")
  if (!tooltip) {
    tooltip = document.createElement("div")
    tooltip.id = "quartz-3d-tooltip"
    tooltip.setAttribute("data-persist", "true")
    document.body.appendChild(tooltip)
  }

  let width = window.innerWidth
  let height = window.innerHeight

  const scene = new THREE.Scene()
  const isDark =
    document.documentElement.getAttribute("saved-theme") === "dark" ||
    document.body.classList.contains("dark")
  const bgHex = isDark ? 0x0f172a : 0xfaf8f8
  scene.fog = new THREE.FogExp2(bgHex, 0.0011)

  function getAdaptiveCameraZ(w: number, h: number): number {
    const aspect = w / h
    if (aspect < 0.6) {
      return 1150
    } else if (aspect < 1.0) {
      return 920
    } else if (w < 1200) {
      return 820
    }
    return 720
  }

  const camera = new THREE.PerspectiveCamera(50, width / height, 1, 3500)
  camera.position.set(0, 0, getAdaptiveCameraZ(width, height))

  const renderer = new THREE.WebGLRenderer({
    canvas,
    antialias: true,
    alpha: true,
    powerPreference: "high-performance",
  })
  renderer.setSize(width, height)
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2))

  // Lights
  const ambientLight = new THREE.AmbientLight(0xffffff, 1.25)
  scene.add(ambientLight)
  const dirLight = new THREE.DirectionalLight(0xffffff, 0.85)
  dirLight.position.set(300, 500, 400)
  scene.add(dirLight)
  const backLight = new THREE.DirectionalLight(0xdbeafe, 0.4)
  backLight.position.set(-300, -200, -300)
  scene.add(backLight)

  const graphGroup = new THREE.Group()
  scene.add(graphGroup)

  // ========================================================
  // 1. 高空流星雨特效 (Meteor Shower / Shooting Stars)
  // ========================================================
  const meteorCount = 18
  interface Meteor {
    pos: any
    speed: number
    len: number
  }
  const meteors: Meteor[] = []
  const meteorDir = new THREE.Vector3(-0.76, -0.65, -0.05).normalize()
  const meteorGeo = new THREE.BufferGeometry()
  const meteorPositions = new Float32Array(meteorCount * 2 * 3)
  const meteorColors = new Float32Array(meteorCount * 2 * 3)

  const headColor = isDark ? new THREE.Color(0xe2e8f0) : new THREE.Color(0x334155)
  const tailColor = isDark ? new THREE.Color(0x1e293b) : new THREE.Color(0xf1f5f9)

  for (let i = 0; i < meteorCount; i++) {
    const m: Meteor = {
      pos: new THREE.Vector3(
        -400 + Math.random() * 1100,
        150 + Math.random() * 650,
        -350 + Math.random() * 500,
      ),
      speed: 4.8 + Math.random() * 4.2,
      len: 90 + Math.random() * 70,
    }
    meteors.push(m)

    // Vertex colors: head is solid, tail is faint
    meteorColors[i * 6] = headColor.r
    meteorColors[i * 6 + 1] = headColor.g
    meteorColors[i * 6 + 2] = headColor.b
    meteorColors[i * 6 + 3] = tailColor.r
    meteorColors[i * 6 + 4] = tailColor.g
    meteorColors[i * 6 + 5] = tailColor.b
  }
  meteorGeo.setAttribute("position", new THREE.BufferAttribute(meteorPositions, 3))
  meteorGeo.setAttribute("color", new THREE.BufferAttribute(meteorColors, 3))

  const meteorMat = new THREE.LineBasicMaterial({
    vertexColors: true,
    transparent: true,
    opacity: 0.65,
    linewidth: 1.5,
  })
  const meteorLines = new THREE.LineSegments(meteorGeo, meteorMat)
  scene.add(meteorLines) // Independent of graphGroup so they streak through background

  // Meteor sparkles at head
  const sparkleGeo = new THREE.BufferGeometry()
  const sparklePositions = new Float32Array(meteorCount * 3)
  sparkleGeo.setAttribute("position", new THREE.BufferAttribute(sparklePositions, 3))
  const sparkleMat = new THREE.PointsMaterial({
    color: isDark ? 0xffffff : 0x284b63,
    size: 3.5,
    transparent: true,
    opacity: 0.85,
    sizeAttenuation: true,
  })
  const sparklePoints = new THREE.Points(sparkleGeo, sparkleMat)
  scene.add(sparklePoints)

  // ========================================================
  // 2. 外围伴生星尘粒子 (Ambient Satellite Constellation)
  // ========================================================
  const satCount = 140
  const satGeo = new THREE.BufferGeometry()
  const satPositions = new Float32Array(satCount * 3)
  const satPhases: number[] = []
  for (let i = 0; i < satCount; i++) {
    const u = Math.random()
    const v = Math.random()
    const theta = u * 2.0 * Math.PI
    const phi = Math.acos(2.0 * v - 1.0)
    const r = 480 + Math.random() * 400
    satPositions[i * 3] = r * Math.sin(phi) * Math.cos(theta)
    satPositions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta) * 0.75
    satPositions[i * 3 + 2] = r * Math.cos(phi)
    satPhases.push(Math.random() * Math.PI * 2)
  }
  satGeo.setAttribute("position", new THREE.BufferAttribute(satPositions, 3))
  const satMat = new THREE.PointsMaterial({
    color: isDark ? 0x94a3b8 : 0x64748b,
    size: 2.8,
    transparent: true,
    opacity: 0.38,
    sizeAttenuation: true,
  })
  const satPoints = new THREE.Points(satGeo, satMat)
  graphGroup.add(satPoints)

  // ========================================================
  // 3. 3D 知识图谱节点与行星环拓扑构建
  // ========================================================
  interface NodeData {
    slug: string
    title: string
    chapter: string
    rawChapter: string
    neighbors: Set<string>
    mesh: any
    halo: any
    ring?: any
    ring2?: any
    origRadius: number
    floatPhase: number
    basePos: any
    currentPos: any
    velocity: any
  }

  const nodes: NodeData[] = []
  const nodeMap = new Map<string, NodeData>()
  const nodeMeshes: any[] = []
  const spinningRings: any[] = []

  let linesMesh: any = null
  let linkNodePairs: { n1: NodeData; n2: NodeData }[] = []

  fetch("/static/contentIndex.json")
    .then((r) => r.json())
    .then((data) => {
      const slugs = Object.keys(data)
      const chapters = Array.from(
        new Set(
          slugs.map((s) => {
            const p = s.split("/")
            return p.length > 1 ? p[0] : "00-MOC"
          }),
        ),
      )

      // Chapter hubs on Fibonacci sphere
      const chapterCoords = new Map<string, any>()
      chapters.forEach((chap, idx) => {
        if (chap.includes("00-moc")) {
          chapterCoords.set(chap, new THREE.Vector3(0, 0, 0))
          return
        }
        const phi = Math.acos(1 - (2 * (idx + 0.5)) / chapters.length)
        const theta = Math.PI * (1 + Math.sqrt(5)) * idx
        const r = 320
        chapterCoords.set(
          chap,
          new THREE.Vector3(
            r * Math.sin(phi) * Math.cos(theta),
            r * Math.sin(phi) * Math.sin(theta) * 0.8,
            r * Math.cos(phi),
          ),
        )
      })

      // Create Nodes
      slugs.forEach((slug) => {
        const item = data[slug]
        let cleanTitle = item.title || slug.split("/").pop() || slug
        cleanTitle = cleanTitle.replace(/^[0-9]+[.-]?\s*/, "")
        const parts = slug.split("/")
        const rawChap = parts.length > 1 ? parts[0] : "00-MOC"
        const cleanChap = rawChap.replace(/^[0-9]+[.-]?\s*/, "")

        const n: NodeData = {
          slug,
          title: cleanTitle,
          chapter: cleanChap,
          rawChapter: rawChap,
          neighbors: new Set(),
          mesh: null,
          halo: null,
          origRadius: 5,
          floatPhase: Math.random() * Math.PI * 2,
          basePos: new THREE.Vector3(),
          currentPos: new THREE.Vector3(),
          velocity: new THREE.Vector3(),
        }

        const center = chapterCoords.get(rawChap) || new THREE.Vector3(0, 0, 0)
        if (slug.includes("00-web安全与ctf知识地图总览")) {
          n.basePos.set(0, 0, 0)
        } else {
          const u = Math.random()
          const v = Math.random()
          const theta = u * 2.0 * Math.PI
          const phi = Math.acos(2.0 * v - 1.0)
          const rad = 45 + Math.random() * 85
          n.basePos.set(
            center.x + rad * Math.sin(phi) * Math.cos(theta),
            center.y + rad * Math.sin(phi) * Math.sin(theta),
            center.z + rad * Math.cos(phi),
          )
        }
        n.currentPos.copy(n.basePos)

        nodeMap.set(slug, n)
        nodes.push(n)
      })

      // Build Link Connections
      slugs.forEach((slug) => {
        const item = data[slug]
        const n = nodeMap.get(slug)
        if (!n) return
        const links = item.links || []
        links.forEach((targetSlug: string) => {
          if (nodeMap.has(targetSlug) && targetSlug !== slug) {
            n.neighbors.add(targetSlug)
            nodeMap.get(targetSlug)!.neighbors.add(slug)
          }
        })
      })

      // 3D Force Relaxation
      for (let iter = 0; iter < 40; iter++) {
        for (let i = 0; i < nodes.length; i++) {
          for (let j = i + 1; j < nodes.length; j++) {
            const n1 = nodes[i]
            const n2 = nodes[j]
            const dx = n1.basePos.x - n2.basePos.x
            const dy = n1.basePos.y - n2.basePos.y
            const dz = n1.basePos.z - n2.basePos.z
            const distSq = dx * dx + dy * dy + dz * dz
            if (distSq < 1600 && distSq > 0.01) {
              const dist = Math.sqrt(distSq)
              const push = (40 - dist) * 0.04
              const nx = (dx / dist) * push
              const ny = (dy / dist) * push
              const nz = (dz / dist) * push
              if (!n1.slug.includes("00-web安全")) n1.basePos.add(new THREE.Vector3(nx, ny, nz))
              if (!n2.slug.includes("00-web安全")) n2.basePos.add(new THREE.Vector3(-nx, -ny, -nz))
            }
          }
        }
      }
      nodes.forEach((n) => n.currentPos.copy(n.basePos))

      // Create Advanced Meshes & Planetary Rings
      const sphereGeo = new THREE.SphereGeometry(1, 20, 16)
      const coreColor = isDark ? 0x7b97aa : 0x284b63
      const regularColor = isDark ? 0x94a3b8 : 0x475569

      nodes.forEach((n) => {
        const isCore = n.slug.includes("00-web安全")
        const isHub = !isCore && (n.neighbors.size > 7 || n.slug.endsWith("/index"))
        const radius = isCore ? 14 : isHub ? 8.5 : Math.max(4.2, Math.min(6.8, 3.8 + n.neighbors.size * 0.35))
        n.origRadius = radius

        // Premium Material with specular highlight
        const mat = new THREE.MeshStandardMaterial({
          color: isCore ? coreColor : isHub ? (isDark ? 0x64748b : 0x334155) : regularColor,
          roughness: isCore ? 0.15 : 0.22,
          metalness: isCore ? 0.35 : 0.2,
          transparent: true,
          opacity: 0.96,
        })

        const mesh = new THREE.Mesh(sphereGeo, mat)
        mesh.scale.set(radius, radius, radius)
        mesh.position.copy(n.currentPos)
        ;(mesh as any).nodeData = n
        n.mesh = mesh

        // Outer translucent silhouette halo
        const haloMat = new THREE.MeshBasicMaterial({
          color: isCore ? coreColor : regularColor,
          transparent: true,
          opacity: 0.15,
          side: THREE.BackSide,
        })
        const halo = new THREE.Mesh(sphereGeo, haloMat)
        halo.scale.set(radius * 1.45, radius * 1.45, radius * 1.45)
        halo.position.copy(n.currentPos)
        n.halo = halo

        graphGroup.add(mesh)
        graphGroup.add(halo)
        nodeMeshes.push(mesh)

        // Advanced Rings for Central MOC and Chapter Hubs
        if (isCore) {
          const ringMat = new THREE.MeshBasicMaterial({
            color: coreColor,
            transparent: true,
            opacity: 0.45,
            wireframe: false,
          })
          const ring1 = new THREE.Mesh(new THREE.TorusGeometry(20, 0.45, 8, 36), ringMat)
          ring1.rotation.x = Math.PI / 4
          ring1.position.copy(n.currentPos)
          graphGroup.add(ring1)
          n.ring = ring1
          spinningRings.push({ mesh: ring1, rotSpeedX: 0.015, rotSpeedZ: 0.02 })

          const ring2 = new THREE.Mesh(new THREE.TorusGeometry(26, 0.35, 8, 36), ringMat)
          ring2.rotation.y = -Math.PI / 3
          ring2.position.copy(n.currentPos)
          graphGroup.add(ring2)
          n.ring2 = ring2
          spinningRings.push({ mesh: ring2, rotSpeedX: -0.012, rotSpeedZ: 0.018 })
        } else if (isHub) {
          const hubRingMat = new THREE.MeshBasicMaterial({
            color: isDark ? 0x94a3b8 : 0x475569,
            transparent: true,
            opacity: 0.35,
          })
          const hubRing = new THREE.Mesh(new THREE.TorusGeometry(radius * 1.6, 0.3, 6, 28), hubRingMat)
          hubRing.rotation.x = Math.random() * Math.PI
          hubRing.rotation.y = Math.random() * Math.PI
          hubRing.position.copy(n.currentPos)
          graphGroup.add(hubRing)
          n.ring = hubRing
          spinningRings.push({
            mesh: hubRing,
            rotSpeedX: 0.008 + Math.random() * 0.01,
            rotSpeedZ: 0.012 + Math.random() * 0.01,
          })
        }
      })

      // Create 3D Link Segments
      const linkPositions: number[] = []
      const processedLinks = new Set<string>()

      nodes.forEach((n) => {
        n.neighbors.forEach((nbrSlug) => {
          const key = [n.slug, nbrSlug].sort().join("::")
          if (processedLinks.has(key)) return
          processedLinks.add(key)
          const target = nodeMap.get(nbrSlug)
          if (!target) return
          linkNodePairs.push({ n1: n, n2: target })
          linkPositions.push(
            n.currentPos.x,
            n.currentPos.y,
            n.currentPos.z,
            target.currentPos.x,
            target.currentPos.y,
            target.currentPos.z,
          )
        })
      })

      const lineGeo = new THREE.BufferGeometry()
      lineGeo.setAttribute("position", new THREE.Float32BufferAttribute(linkPositions, 3))
      const lineMat = new THREE.LineBasicMaterial({
        color: isDark ? 0x475569 : 0x94a3b8,
        transparent: true,
        opacity: 0.32,
      })
      linesMesh = new THREE.LineSegments(lineGeo, lineMat)
      graphGroup.add(linesMesh)
    })

  // Mouse & Auto-Orbit Variables
  let mouseX = 0
  let mouseY = 0
  let mouseParallaxX = 0
  let mouseParallaxY = 0
  let autoOrbitAngleY = 0
  let isDragging = false
  let prevMouseX = 0
  let prevMouseY = 0
  let dragRotX = 0
  let dragRotY = 0
  const raycaster = new THREE.Raycaster()
  const mouseNDC = new THREE.Vector2(-999, -999)
  let hoveredNode: NodeData | null = null

  // Mouse Listeners
  window.addEventListener("mousemove", (e) => {
    mouseX = e.clientX
    mouseY = e.clientY
    mouseNDC.x = (e.clientX / width) * 2 - 1
    mouseNDC.y = -(e.clientY / height) * 2 + 1

    if (isDragging) {
      const deltaX = e.clientX - prevMouseX
      const deltaY = e.clientY - prevMouseY
      dragRotY += deltaX * 0.005
      dragRotX += deltaY * 0.005
      prevMouseX = e.clientX
      prevMouseY = e.clientY
    } else {
      mouseParallaxY = ((e.clientX / width) - 0.5) * 1.25
      mouseParallaxX = ((e.clientY / height) - 0.5) * 0.85
    }
  })

  window.addEventListener("mousedown", (e) => {
    if (e.target === canvas) {
      isDragging = true
      prevMouseX = e.clientX
      prevMouseY = e.clientY
    }
  })

  window.addEventListener("mouseup", () => {
    isDragging = false
  })

  window.addEventListener(
    "wheel",
    (e) => {
      camera.position.z += e.deltaY * 0.5
      camera.position.z = Math.max(380, Math.min(1300, camera.position.z))
    },
    { passive: true },
  )

  window.addEventListener("click", (e) => {
    if (hoveredNode && e.target === canvas) {
      window.location.href = "/" + encodeURI(hoveredNode.slug)
    }
  })

  // Touch Gesture Listeners (Mobile Interaction: Drag, Pinch Zoom, Tap)
  let touchStartDist = 0
  let isTouching = false
  let touchStartX = 0
  let touchStartY = 0
  let touchMoved = false
  let touchStartTime = 0

  canvas.addEventListener(
    "touchstart",
    (e: TouchEvent) => {
      if (e.touches.length === 1) {
        isTouching = true
        isDragging = true
        touchMoved = false
        touchStartTime = Date.now()
        const t = e.touches[0]
        prevMouseX = t.clientX
        prevMouseY = t.clientY
        touchStartX = t.clientX
        touchStartY = t.clientY
      } else if (e.touches.length === 2) {
        isDragging = false
        const t1 = e.touches[0]
        const t2 = e.touches[1]
        touchStartDist = Math.hypot(t1.clientX - t2.clientX, t1.clientY - t2.clientY)
      }
    },
    { passive: true },
  )

  canvas.addEventListener(
    "touchmove",
    (e: TouchEvent) => {
      if (e.touches.length === 1 && isDragging) {
        const t = e.touches[0]
        const deltaX = t.clientX - prevMouseX
        const deltaY = t.clientY - prevMouseY
        if (Math.abs(t.clientX - touchStartX) > 6 || Math.abs(t.clientY - touchStartY) > 6) {
          touchMoved = true
        }
        dragRotY += deltaX * 0.007
        dragRotX += deltaY * 0.007
        prevMouseX = t.clientX
        prevMouseY = t.clientY
      } else if (e.touches.length === 2) {
        touchMoved = true
        const t1 = e.touches[0]
        const t2 = e.touches[1]
        const newDist = Math.hypot(t1.clientX - t2.clientX, t1.clientY - t2.clientY)
        if (touchStartDist > 0) {
          const deltaDist = newDist - touchStartDist
          camera.position.z -= deltaDist * 1.8
          camera.position.z = Math.max(380, Math.min(1800, camera.position.z))
        }
        touchStartDist = newDist
      }
    },
    { passive: true },
  )

  canvas.addEventListener(
    "touchend",
    (e: TouchEvent) => {
      if (e.touches.length === 0) {
        isDragging = false
        isTouching = false
        // Tap gesture detection (tap without dragging)
        const touchDuration = Date.now() - touchStartTime
        if (!touchMoved && touchDuration < 320) {
          const tapNDC = new THREE.Vector2(
            (touchStartX / width) * 2 - 1,
            -(touchStartY / height) * 2 + 1,
          )
          raycaster.setFromCamera(tapNDC, camera)
          const intersects = raycaster.intersectObjects(nodeMeshes)
          if (intersects.length > 0) {
            const hit = intersects[0].object as any
            const node = hit.nodeData as NodeData
            if (node) {
              window.location.href = "/" + encodeURI(node.slug)
            }
          }
        }
      } else if (e.touches.length === 1) {
        const t = e.touches[0]
        prevMouseX = t.clientX
        prevMouseY = t.clientY
      }
    },
    { passive: true },
  )

  function resize() {
    const prevAspect = width / height
    width = window.innerWidth
    height = window.innerHeight
    camera.aspect = width / height
    camera.updateProjectionMatrix()
    renderer.setSize(width, height)
    // If aspect ratio shifted (e.g. phone flipped from portrait to landscape)
    if (Math.abs(width / height - prevAspect) > 0.25) {
      camera.position.z = getAdaptiveCameraZ(width, height)
    }
  }
  window.addEventListener("resize", resize)

  // Animation Loop
  let clockTime = 0
  graph3DRunning = true

  function animate() {
    if (!graph3DRunning) return
    graph3DAnimId = requestAnimationFrame(animate)
    clockTime += 0.016

    // ========================================================
    // A. 鼠标不动时自行平缓公转与呼吸起伏
    // ========================================================
    autoOrbitAngleY += 0.0018 // 持续平稳自转
    const autoBreatheAngleX = Math.sin(clockTime * 0.35) * 0.08

    if (!isDragging) {
      const targetY = autoOrbitAngleY + dragRotY + mouseParallaxY
      const targetX = autoBreatheAngleX + dragRotX + mouseParallaxX
      graphGroup.rotation.y += (targetY - graphGroup.rotation.y) * 0.045
      graphGroup.rotation.x += (targetX - graphGroup.rotation.x) * 0.045
    }

    // 旋转行星环 (Gyroscopic Rings)
    spinningRings.forEach((r) => {
      r.mesh.rotation.x += r.rotSpeedX
      r.mesh.rotation.z += r.rotSpeedZ
    })

    // ========================================================
    // B. 更新流星雨运动 (Shooting Stars / Meteors)
    // ========================================================
    const meteorPosAttr = meteorGeo.attributes.position as any
    const sparklePosAttr = sparkleGeo.attributes.position as any

    if (meteorPosAttr) {
      for (let i = 0; i < meteorCount; i++) {
        const m = meteors[i]
        m.pos.addScaledVector(meteorDir, m.speed)

        // Reset if meteor travels below screen
        if (m.pos.y < -550 || m.pos.x < -800) {
          m.pos.set(
            250 + Math.random() * 650,
            450 + Math.random() * 400,
            -350 + Math.random() * 450,
          )
          m.speed = 4.8 + Math.random() * 4.2
          m.len = 90 + Math.random() * 70
        }

        // Head position
        const hx = m.pos.x
        const hy = m.pos.y
        const hz = m.pos.z

        // Tail position
        const tx = hx - meteorDir.x * m.len
        const ty = hy - meteorDir.y * m.len
        const tz = hz - meteorDir.z * m.len

        meteorPosAttr.setXYZ(i * 2, hx, hy, hz)
        meteorPosAttr.setXYZ(i * 2 + 1, tx, ty, tz)

        if (sparklePosAttr) {
          sparklePosAttr.setXYZ(i, hx, hy, hz)
        }
      }
      meteorPosAttr.needsUpdate = true
      if (sparklePosAttr) sparklePosAttr.needsUpdate = true
    }

    // ========================================================
    // C. 外围伴生星尘轻缓律动
    // ========================================================
    const posAttr = satGeo.attributes.position as any
    if (posAttr) {
      for (let i = 0; i < satCount; i++) {
        const ph = satPhases[i]
        const origY = satPositions[i * 3 + 1]
        posAttr.setY(i, origY + Math.sin(clockTime * 1.5 + ph) * 18)
      }
      posAttr.needsUpdate = true
    }

    // ========================================================
    // D. 各个星球微幅自主律动浮沉 & 连线实时动态更新
    // ========================================================
    nodes.forEach((n) => {
      if (!n.mesh) return
      // Gentle floating harmonic oscillation
      const floatY = Math.sin(clockTime * 1.8 + n.floatPhase) * 3.2
      const floatX = Math.cos(clockTime * 1.4 + n.floatPhase) * 2.2
      const floatZ = Math.sin(clockTime * 1.2 + n.floatPhase) * 2.6

      n.mesh.position.set(
        n.currentPos.x + floatX,
        n.currentPos.y + floatY,
        n.currentPos.z + floatZ,
      )
      if (n.halo) n.halo.position.copy(n.mesh.position)
      if (n.ring) n.ring.position.copy(n.mesh.position)
      if (n.ring2) n.ring2.position.copy(n.mesh.position)
    })

    if (linesMesh && linkNodePairs.length > 0) {
      const linePosAttr = linesMesh.geometry.attributes.position as any
      if (linePosAttr) {
        for (let i = 0; i < linkNodePairs.length; i++) {
          const pair = linkNodePairs[i]
          if (pair.n1.mesh && pair.n2.mesh) {
            linePosAttr.setXYZ(
              i * 2,
              pair.n1.mesh.position.x,
              pair.n1.mesh.position.y,
              pair.n1.mesh.position.z,
            )
            linePosAttr.setXYZ(
              i * 2 + 1,
              pair.n2.mesh.position.x,
              pair.n2.mesh.position.y,
              pair.n2.mesh.position.z,
            )
          }
        }
        linePosAttr.needsUpdate = true
      }
    }

    // ========================================================
    // E. 鼠标射线检测、力场涟漪与子网聚光
    // ========================================================
    raycaster.setFromCamera(mouseNDC, camera)
    const intersects = raycaster.intersectObjects(nodeMeshes)

    if (intersects.length > 0) {
      const hit = intersects[0].object as any
      const node = hit.nodeData as NodeData
      if (node && hoveredNode !== node) {
        hoveredNode = node
        canvas.classList.add("pointer") // 激活高反差暗黑微雕指针

        // Update Tooltip
        if (tooltip) {
          tooltip.innerHTML = `
            <div class="tt-badge">${node.chapter}</div>
            <div class="tt-title">${node.title}</div>
            <div class="tt-hint">点击直接阅读 ➔</div>
          `
          tooltip.className = "visible"
        }

        // Highlight Subgraph in 3D
        nodes.forEach((n) => {
          const isTarget = n === node
          const isNeighbor = node.neighbors.has(n.slug)
          if (n.mesh) {
            const mat = n.mesh.material
            if (isTarget) {
              mat.opacity = 1.0
              const s = n.origRadius * 1.5
              n.mesh.scale.set(s, s, s)
              if (n.halo) n.halo.material.opacity = 0.45
            } else if (isNeighbor) {
              mat.opacity = 0.95
              mat.color.setHex(0x284b63)
            } else {
              mat.opacity = 0.16
            }
          }
        })
      }
    } else {
      if (hoveredNode) {
        hoveredNode = null
        canvas.classList.remove("pointer")
        if (tooltip) tooltip.className = ""

        // Reset all nodes
        nodes.forEach((n) => {
          if (n.mesh) {
            n.mesh.scale.set(n.origRadius, n.origRadius, n.origRadius)
            n.mesh.material.opacity = 0.96
            n.mesh.material.color.setHex(
              n.slug.includes("00-web安全") || n.neighbors.size > 8
                ? (isDark ? 0x7b97aa : 0x284b63)
                : (isDark ? 0x94a3b8 : 0x475569),
            )
            if (n.halo) n.halo.material.opacity = 0.15
          }
        })
      }
    }

    // Tooltip follows 3D projected coordinate
    if (hoveredNode && hoveredNode.mesh && tooltip && tooltip.classList.contains("visible")) {
      const wp = new THREE.Vector3()
      hoveredNode.mesh.getWorldPosition(wp)
      wp.project(camera)
      const sx = ((wp.x + 1) * width) / 2
      const sy = ((-wp.y + 1) * height) / 2
      tooltip.style.left = sx + "px"
      tooltip.style.top = sy + "px"
    }

    // Elastic Kinetic Impulse near mouse ray
    if (mouseNDC.x > -1 && mouseNDC.x < 1 && mouseNDC.y > -1 && mouseNDC.y < 1) {
      nodes.forEach((n) => {
        if (!n.mesh) return
        const wp = new THREE.Vector3()
        n.mesh.getWorldPosition(wp)
        const distToRay = raycaster.ray.distanceToPoint(wp)
        if (distToRay < 75 && distToRay > 5) {
          const push = ((75 - distToRay) / 75) * 1.8
          const dir = new THREE.Vector3().subVectors(wp, raycaster.ray.origin).normalize()
          n.velocity.addScaledVector(dir, push)
        }
        // Spring physics
        n.velocity.add(new THREE.Vector3().subVectors(n.basePos, n.currentPos).multiplyScalar(0.08))
        n.velocity.multiplyScalar(0.82)
        n.currentPos.add(n.velocity)
      })
    }

    renderer.render(scene, camera)
  }

  animate()
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", checkAndInit3DGraph)
  } else {
    checkAndInit3DGraph()
  }
  document.addEventListener("nav", checkAndInit3DGraph)
}
