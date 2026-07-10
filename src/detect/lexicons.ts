/**
 * Category lexicons for Layer 3 (sensitive disclosure heuristics).
 * These are deliberately plain string lists so anyone can audit exactly what
 * the tool looks for. Nothing here leaves your machine.
 */

/** ~380 common medications (generic + brand), excluding psychiatric meds (see MENTAL_MEDS). */
export const MEDICATIONS: string[] = [
  // cardiovascular
  'atorvastatin', 'simvastatin', 'rosuvastatin', 'pravastatin', 'lovastatin', 'pitavastatin',
  'ezetimibe', 'fenofibrate', 'gemfibrozil', 'evolocumab', 'alirocumab', 'lipitor', 'crestor',
  'lisinopril', 'enalapril', 'ramipril', 'benazepril', 'captopril', 'quinapril',
  'losartan', 'valsartan', 'olmesartan', 'irbesartan', 'telmisartan', 'candesartan',
  'sacubitril', 'entresto', 'amlodipine', 'nifedipine', 'felodipine', 'diltiazem', 'verapamil',
  'metoprolol', 'atenolol', 'propranolol', 'carvedilol', 'bisoprolol', 'nebivolol', 'labetalol',
  'hydrochlorothiazide', 'chlorthalidone', 'indapamide', 'furosemide', 'torsemide', 'bumetanide',
  'spironolactone', 'eplerenone', 'clonidine', 'hydralazine', 'isosorbide', 'nitroglycerin',
  'digoxin', 'amiodarone', 'flecainide', 'sotalol', 'dofetilide', 'dronedarone',
  'warfarin', 'coumadin', 'apixaban', 'eliquis', 'rivaroxaban', 'xarelto', 'dabigatran',
  'pradaxa', 'edoxaban', 'clopidogrel', 'plavix', 'prasugrel', 'ticagrelor', 'brilinta',
  'dipyridamole', 'cilostazol', 'ranolazine', 'ivabradine',
  // diabetes & metabolic
  'metformin', 'glipizide', 'glyburide', 'glimepiride', 'sitagliptin', 'januvia', 'saxagliptin',
  'linagliptin', 'tradjenta', 'empagliflozin', 'jardiance', 'dapagliflozin', 'farxiga',
  'canagliflozin', 'invokana', 'liraglutide', 'victoza', 'saxenda', 'semaglutide', 'ozempic',
  'wegovy', 'rybelsus', 'dulaglutide', 'trulicity', 'exenatide', 'tirzepatide', 'mounjaro',
  'zepbound', 'pioglitazone', 'actos', 'insulin', 'lantus', 'humalog', 'novolog', 'tresiba',
  'levemir', 'toujeo', 'basaglar', 'phentermine', 'orlistat', 'contrave',
  // thyroid & hormones
  'levothyroxine', 'synthroid', 'liothyronine', 'cytomel', 'armour thyroid', 'methimazole',
  'propylthiouracil', 'estradiol', 'premarin', 'progesterone', 'prometrium', 'testosterone',
  'androgel', 'finasteride', 'propecia', 'dutasteride', 'avodart', 'tamsulosin', 'flomax',
  'sildenafil', 'viagra', 'tadalafil', 'cialis', 'vardenafil', 'levitra', 'clomiphene', 'clomid',
  'letrozole', 'femara', 'anastrozole', 'arimidex', 'tamoxifen', 'raloxifene', 'alendronate',
  'fosamax', 'risedronate', 'zoledronic acid', 'denosumab', 'prolia', 'teriparatide', 'forteo',
  'prednisone', 'prednisolone', 'methylprednisolone', 'medrol', 'dexamethasone', 'hydrocortisone',
  'fludrocortisone', 'levonorgestrel', 'norethindrone', 'medroxyprogesterone', 'depo-provera',
  'mirena', 'nexplanon', 'yaz', 'yasmin', 'nuvaring', 'plan b',
  // gastrointestinal
  'omeprazole', 'prilosec', 'esomeprazole', 'nexium', 'lansoprazole', 'prevacid', 'pantoprazole',
  'protonix', 'rabeprazole', 'famotidine', 'pepcid', 'sucralfate', 'misoprostol', 'ondansetron',
  'zofran', 'metoclopramide', 'reglan', 'promethazine', 'phenergan', 'dicyclomine', 'hyoscyamine',
  'loperamide', 'imodium', 'docusate', 'miralax', 'linaclotide', 'linzess', 'lubiprostone',
  'mesalamine', 'lialda', 'sulfasalazine', 'budesonide', 'infliximab', 'remicade', 'adalimumab',
  'humira', 'ustekinumab', 'stelara', 'vedolizumab', 'entyvio', 'ursodiol', 'lactulose',
  'rifaximin', 'xifaxan',
  // antibiotics, antivirals, antifungals
  'amoxicillin', 'augmentin', 'ampicillin', 'penicillin', 'dicloxacillin', 'cephalexin', 'keflex',
  'cefdinir', 'ceftriaxone', 'cefuroxime', 'cefpodoxime', 'azithromycin', 'zithromax',
  'clarithromycin', 'erythromycin', 'doxycycline', 'minocycline', 'tetracycline', 'ciprofloxacin',
  'cipro', 'levofloxacin', 'levaquin', 'moxifloxacin', 'trimethoprim', 'sulfamethoxazole',
  'bactrim', 'nitrofurantoin', 'macrobid', 'clindamycin', 'metronidazole', 'flagyl', 'vancomycin',
  'linezolid', 'gentamicin', 'tobramycin', 'rifampin', 'isoniazid', 'ethambutol', 'pyrazinamide',
  'acyclovir', 'valacyclovir', 'valtrex', 'famciclovir', 'oseltamivir', 'tamiflu', 'remdesivir',
  'paxlovid', 'nirmatrelvir', 'ritonavir', 'tenofovir', 'emtricitabine', 'truvada', 'descovy',
  'biktarvy', 'dolutegravir', 'efavirenz', 'fluconazole', 'diflucan', 'itraconazole',
  'ketoconazole', 'terbinafine', 'lamisil', 'nystatin', 'clotrimazole', 'miconazole', 'ivermectin',
  'hydroxychloroquine', 'plaquenil', 'chloroquine', 'mebendazole', 'albendazole', 'valganciclovir',
  // respiratory & allergy
  'albuterol', 'salbutamol', 'ventolin', 'proair', 'levalbuterol', 'xopenex', 'ipratropium',
  'tiotropium', 'spiriva', 'fluticasone', 'flonase', 'flovent', 'mometasone', 'nasonex',
  'beclomethasone', 'ciclesonide', 'salmeterol', 'formoterol', 'vilanterol', 'montelukast',
  'singulair', 'zafirlukast', 'theophylline', 'advair', 'symbicort', 'breo', 'trelegy', 'dulera',
  'cetirizine', 'zyrtec', 'loratadine', 'claritin', 'fexofenadine', 'allegra', 'levocetirizine',
  'xyzal', 'desloratadine', 'clarinex', 'diphenhydramine', 'benadryl', 'chlorpheniramine',
  'azelastine', 'astelin', 'epinephrine', 'epipen', 'dupilumab', 'dupixent', 'omalizumab',
  'xolair', 'benralizumab', 'mepolizumab', 'guaifenesin', 'mucinex', 'dextromethorphan',
  'pseudoephedrine', 'sudafed', 'phenylephrine',
  // pain, neuro, sleep
  'gabapentin', 'neurontin', 'pregabalin', 'lyrica', 'ibuprofen', 'advil', 'motrin', 'naproxen',
  'aleve', 'meloxicam', 'mobic', 'celecoxib', 'celebrex', 'diclofenac', 'voltaren', 'indomethacin',
  'ketorolac', 'toradol', 'acetaminophen', 'tylenol', 'tramadol', 'ultram', 'codeine',
  'hydrocodone', 'vicodin', 'norco', 'oxycodone', 'oxycontin', 'percocet', 'morphine',
  'hydromorphone', 'dilaudid', 'fentanyl', 'methadone', 'buprenorphine', 'suboxone', 'naloxone',
  'narcan', 'sumatriptan', 'imitrex', 'rizatriptan', 'maxalt', 'zolmitriptan', 'eletriptan',
  'relpax', 'ubrogepant', 'ubrelvy', 'rimegepant', 'nurtec', 'erenumab', 'aimovig', 'fremanezumab',
  'ajovy', 'galcanezumab', 'emgality', 'topiramate', 'topamax', 'divalproex', 'depakote',
  'carbamazepine', 'tegretol', 'oxcarbazepine', 'trileptal', 'phenytoin', 'dilantin',
  'levetiracetam', 'keppra', 'lacosamide', 'vimpat', 'zonisamide', 'ethosuximide', 'primidone',
  'tizanidine', 'zanaflex', 'baclofen', 'cyclobenzaprine', 'flexeril', 'methocarbamol', 'robaxin',
  'carisoprodol', 'soma', 'ropinirole', 'requip', 'pramipexole', 'mirapex', 'carbidopa',
  'levodopa', 'sinemet', 'entacapone', 'rasagiline', 'amantadine', 'donepezil', 'aricept',
  'memantine', 'namenda', 'rivastigmine', 'exelon', 'galantamine', 'riluzole', 'zolpidem',
  'ambien', 'eszopiclone', 'lunesta', 'zaleplon', 'sonata', 'ramelteon', 'rozerem', 'suvorexant',
  'belsomra', 'melatonin', 'botox',
  // oncology & immunology
  'methotrexate', 'cyclophosphamide', 'doxorubicin', 'cisplatin', 'carboplatin', 'oxaliplatin',
  'paclitaxel', 'taxol', 'docetaxel', 'gemcitabine', 'fluorouracil', 'capecitabine', 'xeloda',
  'irinotecan', 'etoposide', 'vincristine', 'rituximab', 'rituxan', 'trastuzumab', 'herceptin',
  'bevacizumab', 'avastin', 'pembrolizumab', 'keytruda', 'nivolumab', 'opdivo', 'ipilimumab',
  'yervoy', 'atezolizumab', 'tecentriq', 'imatinib', 'gleevec', 'dasatinib', 'nilotinib',
  'erlotinib', 'tarceva', 'gefitinib', 'osimertinib', 'tagrisso', 'crizotinib', 'alectinib',
  'vemurafenib', 'dabrafenib', 'trametinib', 'palbociclib', 'ibrance', 'ribociclib',
  'abemaciclib', 'verzenio', 'olaparib', 'lynparza', 'niraparib', 'lenalidomide', 'revlimid',
  'bortezomib', 'velcade', 'daratumumab', 'darzalex', 'ibrutinib', 'imbruvica', 'venetoclax',
  'azacitidine', 'hydroxyurea', 'exemestane', 'fulvestrant', 'leuprolide', 'lupron',
  'bicalutamide', 'enzalutamide', 'xtandi', 'abiraterone', 'zytiga',
  // rheumatology, transplant, dermatology, misc
  'allopurinol', 'colchicine', 'febuxostat', 'probenecid', 'leflunomide', 'azathioprine',
  'imuran', 'mycophenolate', 'cellcept', 'tacrolimus', 'prograf', 'cyclosporine', 'sirolimus',
  'everolimus', 'etanercept', 'enbrel', 'certolizumab', 'cimzia', 'golimumab', 'simponi',
  'tocilizumab', 'actemra', 'tofacitinib', 'xeljanz', 'upadacitinib', 'rinvoq', 'baricitinib',
  'olumiant', 'secukinumab', 'cosentyx', 'ixekizumab', 'taltz', 'guselkumab', 'tremfya',
  'risankizumab', 'skyrizi', 'apremilast', 'otezla', 'isotretinoin', 'accutane', 'tretinoin',
  'retin-a', 'adapalene', 'differin', 'minoxidil', 'rogaine', 'latanoprost', 'xalatan', 'timolol',
  'brimonidine', 'dorzolamide', 'oxybutynin', 'ditropan', 'tolterodine', 'detrol', 'solifenacin',
  'vesicare', 'mirabegron', 'myrbetriq', 'phenazopyridine', 'azo', 'varenicline', 'chantix',
  'desmopressin', 'octreotide',
];

/** Psychiatric / mental-health medications — scored under the more sensitive category. */
export const MENTAL_MEDS: string[] = [
  // SSRIs / SNRIs / atypical antidepressants
  'sertraline', 'zoloft', 'fluoxetine', 'prozac', 'escitalopram', 'lexapro', 'citalopram',
  'celexa', 'paroxetine', 'paxil', 'fluvoxamine', 'luvox', 'venlafaxine', 'effexor',
  'desvenlafaxine', 'pristiq', 'duloxetine', 'cymbalta', 'levomilnacipran', 'fetzima',
  'milnacipran', 'savella', 'bupropion', 'wellbutrin', 'mirtazapine', 'remeron', 'trazodone',
  'nefazodone', 'vilazodone', 'viibryd', 'vortioxetine', 'trintellix', 'agomelatine',
  // tricyclics & MAOIs
  'amitriptyline', 'elavil', 'nortriptyline', 'pamelor', 'imipramine', 'desipramine',
  'clomipramine', 'anafranil', 'doxepin', 'phenelzine', 'nardil', 'tranylcypromine', 'parnate',
  'isocarboxazid', 'selegiline', 'emsam',
  // anxiolytics & benzodiazepines
  'alprazolam', 'xanax', 'clonazepam', 'klonopin', 'lorazepam', 'ativan', 'diazepam', 'valium',
  'temazepam', 'restoril', 'oxazepam', 'chlordiazepoxide', 'librium', 'buspirone', 'buspar',
  'hydroxyzine', 'vistaril',
  // antipsychotics & mood stabilizers
  'quetiapine', 'seroquel', 'aripiprazole', 'abilify', 'risperidone', 'risperdal', 'olanzapine',
  'zyprexa', 'ziprasidone', 'geodon', 'paliperidone', 'invega', 'lurasidone', 'latuda',
  'cariprazine', 'vraylar', 'brexpiprazole', 'rexulti', 'asenapine', 'saphris', 'clozapine',
  'clozaril', 'haloperidol', 'haldol', 'chlorpromazine', 'thorazine', 'fluphenazine',
  'perphenazine', 'lithium', 'lamotrigine', 'lamictal', 'valproate',
  // ADHD & stimulants
  'adderall', 'amphetamine', 'dextroamphetamine', 'dexedrine', 'vyvanse', 'lisdexamfetamine',
  'ritalin', 'methylphenidate', 'concerta', 'focalin', 'dexmethylphenidate', 'strattera',
  'atomoxetine', 'guanfacine', 'intuniv', 'modafinil', 'provigil', 'armodafinil', 'nuvigil',
  // addiction & other
  'esketamine', 'spravato', 'acamprosate', 'campral', 'disulfiram', 'antabuse',
];

/** ~150 health conditions & clinical terms (first-person gated). */
export const HEALTH_CONDITIONS: string[] = [
  'diabetes', 'prediabetes', 'diabetic', 'hypertension', 'high blood pressure', 'hyperlipidemia',
  'high cholesterol', 'asthma', 'copd', 'emphysema', 'bronchitis', 'pneumonia', 'sleep apnea',
  'insomnia', 'migraine', 'migraines', 'epilepsy', 'seizure', 'seizures', 'stroke',
  'heart attack', 'heart disease', 'heart failure', 'arrhythmia', 'atrial fibrillation', 'afib',
  'angina', 'anemia', 'anaemia', 'leukemia', 'lymphoma', 'melanoma', 'carcinoma', 'cancer',
  'tumor', 'tumour', 'fibroid', 'endometriosis', 'pcos', 'infertility', 'ivf', 'miscarriage',
  'pregnancy', 'pregnant', 'menopause', 'osteoporosis', 'arthritis', 'rheumatoid',
  'osteoarthritis', 'gout', 'lupus', 'fibromyalgia', 'psoriasis', 'eczema', 'dermatitis',
  'rosacea', 'shingles', 'herpes', 'hpv', 'hiv', 'hepatitis', 'chlamydia', 'gonorrhea',
  'syphilis', 'uti', 'kidney stone', 'kidney stones', 'kidney disease', 'dialysis', 'cirrhosis',
  'fatty liver', 'gallstones', 'pancreatitis', 'appendicitis', 'hernia', 'ulcer', 'gerd',
  'acid reflux', 'ibs', 'crohn', "crohn's", 'colitis', 'celiac', 'diverticulitis', 'hemorrhoid',
  'hemorrhoids', 'hypothyroid', 'hypothyroidism', 'hyperthyroid', 'hyperthyroidism', 'hashimoto',
  "hashimoto's", 'graves disease', 'adrenal', 'concussion', 'fracture', 'fractured', 'sciatica',
  'scoliosis', 'herniated disc', 'carpal tunnel', 'tendonitis', 'tendinitis', 'bursitis',
  'plantar fasciitis', 'glaucoma', 'cataract', 'cataracts', 'macular degeneration', 'tinnitus',
  'vertigo', "alzheimer", "alzheimer's", 'dementia', 'parkinson', "parkinson's",
  'multiple sclerosis', 'neuropathy', 'chronic pain', 'chronic fatigue', 'long covid',
  'mononucleosis', 'strep throat', 'sinusitis', 'tonsillitis', 'appendectomy', 'biopsy',
  'chemotherapy', 'chemo', 'radiation therapy', 'transplant', 'stent', 'pacemaker',
  'bypass surgery', 'blood clot', 'dvt', 'embolism', 'aneurysm', 'sepsis', 'cellulitis',
  'abscess', 'covid', 'hospitalized', 'hospitalised', 'emergency room', 'urgent care', 'er visit',
  'diagnosed with', 'flare up', 'autoimmune',
];

/** Health phrases that are sufficient on their own (inherently first-person). */
export const HEALTH_SELF: string[] = [
  'my diagnosis', 'my doctor', 'my physician', 'my surgeon', 'my cardiologist',
  'my dermatologist', 'my oncologist', 'my neurologist', 'my gynecologist', 'my urologist',
  'my gp', 'my symptoms', 'my medication', 'my meds', 'my prescription', 'my surgery',
  'my condition', 'my illness', 'my disease', 'my treatment', 'my blood pressure',
  'my blood sugar', 'my a1c', 'my cholesterol', 'my mri', 'my ct scan', 'my x-ray',
  'my lab results', 'my test results', 'my biopsy', 'my period', 'my allergies', 'my allergy',
  'my injury', 'my dose', 'my dosage',
];

/** Mental-health terms (first-person gated) — kept separate; more sensitive. */
export const MENTAL_TERMS: string[] = [
  'depression', 'depressed', 'anxiety', 'anxious', 'panic attack', 'panic attacks',
  'panic disorder', 'adhd', 'autism', 'autistic', 'aspergers', "asperger's", 'bipolar', 'mania',
  'manic', 'hypomania', 'schizophrenia', 'schizoaffective', 'psychosis', 'psychotic', 'ptsd',
  'cptsd', 'trauma', 'traumatized', 'ocd', 'intrusive thoughts', 'eating disorder', 'anorexia',
  'bulimia', 'binge eating', 'body dysmorphia', 'self-harm', 'self harm', 'suicidal', 'suicide',
  'kill myself', 'end my life', 'want to die', 'hopeless', 'burnout', 'burned out', 'burnt out',
  'dissociation', 'dissociating', 'derealization', 'depersonalization', 'agoraphobia',
  'social anxiety', 'grief', 'grieving', 'addiction', 'addicted', 'alcoholic', 'alcoholism',
  'relapse', 'relapsed', 'sober', 'sobriety', 'withdrawal', 'rehab', 'antidepressant',
  'antidepressants',
];

export const MENTAL_SELF: string[] = [
  'my therapist', 'my therapy', 'in therapy', 'my psychiatrist', 'my psychologist',
  'my counselor', 'my counsellor', 'my mental health', 'my depression', 'my anxiety', 'my adhd',
  'my ocd', 'my ptsd', 'my trauma', 'my panic attacks', 'seeing a therapist', 'started therapy',
  'my psych', 'my meds for anxiety', 'my antidepressant',
];

export const LEGAL_TERMS: string[] = [
  'lawsuit', 'sue', 'sued', 'suing', 'divorce', 'divorced', 'custody', 'arrest', 'arrested',
  'dui', 'dwi', 'felony', 'misdemeanor', 'probation', 'parole', 'deportation', 'deported',
  'asylum', 'immigration status', 'restraining order', 'subpoena', 'subpoenaed', 'deposition',
  'plea deal', 'child support', 'alimony', 'court order', 'court date', 'small claims',
  'eviction', 'evicted', 'incarcerated', 'jail', 'prison', 'warrant', 'settlement',
  'wrongful termination', 'discrimination case',
];

export const LEGAL_SELF: string[] = [
  'my lawyer', 'my attorney', 'my legal case', 'my court date', 'my divorce', 'my custody',
  'my visa', 'my green card', 'my immigration', 'my citizenship', 'my criminal record',
  'my arrest', 'my dui', 'my probation', 'my parole', 'my restraining order', 'my settlement',
  'my lawsuit', 'my hearing', 'my case worker', 'my immigration lawyer',
];

export const FINANCIAL_TERMS: string[] = [
  'salary', 'debt', 'bankruptcy', 'bankrupt', 'foreclosure', 'collections', 'garnished',
  'garnishment', 'payday loan', 'overdraft', 'in debt', 'paycheck to paycheck', "can't afford",
  'cannot afford', 'maxed out', 'behind on payments', 'behind on rent', 'credit score',
  'student loans', 'net worth',
];

export const FINANCIAL_SELF: string[] = [
  'my salary', 'my income', 'my debt', 'my savings', 'my mortgage', 'my rent', 'my loan',
  'my loans', 'my credit score', 'my credit card debt', 'my 401k', 'my ira', 'my retirement',
  'my bank account', 'my checking account', 'my savings account', 'my paycheck', 'my net worth',
  'my student loans', 'my bills', 'i owe', 'my budget', 'my investments', 'my portfolio',
  'my raise', 'my bonus', 'my financial situation', 'my finances', 'my crypto',
];

export const EMPLOYMENT_TERMS: string[] = [
  'resignation', 'resigning', 'quit my job', 'quitting my job', 'layoffs', 'laid off', 'fired',
  'terminated', 'severance', 'nda', 'non-disclosure', 'confidential', 'proprietary',
  'trade secret', 'internal only', 'do not distribute', 'performance improvement plan',
  'hostile work environment', 'two weeks notice',
];

export const EMPLOYMENT_SELF: string[] = [
  'my boss', 'my manager', 'my coworker', 'my co-worker', 'my colleague', 'my company',
  'my employer', 'my team lead', 'my supervisor', 'my hr', 'my performance review',
  'my offer letter', 'my resignation', 'my startup', 'my interview', 'i got fired',
  'i was fired', 'i was laid off', 'i got laid off', 'fired me', 'laid me off', 'my noncompete',
  'my non-compete', 'my severance', 'my promotion', 'my demotion', 'my pip', 'my clients',
  'my workplace',
];

export const RELATIONSHIP_TERMS: string[] = [
  'broke up', 'breakup', 'cheated on', 'cheating on', 'affair', 'engaged',
];

export const RELATIONSHIP_SELF: string[] = [
  'my wife', 'my husband', 'my spouse', 'my girlfriend', 'my boyfriend', 'my partner',
  'my fiancé', 'my fiancée', 'my fiance', 'my fiancee', 'my ex', 'my ex-wife', 'my ex-husband',
  'my mom', 'my mother', 'my dad', 'my father', 'my parents', 'my son', 'my daughter', 'my kids',
  'my children', 'my child', 'my baby', 'my brother', 'my sister', 'my siblings', 'my grandma',
  'my grandmother', 'my grandpa', 'my grandfather', 'my aunt', 'my uncle', 'my cousin',
  'my nephew', 'my niece', 'my in-laws', 'my mother-in-law', 'my father-in-law', 'my stepmom',
  'my stepdad', 'my stepson', 'my stepdaughter', 'my best friend', 'my roommate', 'my neighbor',
  'my landlord', 'my marriage', 'my relationship', 'my family',
];

export const IDENTITY_SELF: string[] = [
  'my name is', 'my full name', 'my legal name', 'my email is', 'my email address is',
  'my phone number is', 'my address is', 'my home address', 'i live at', 'my birthday is',
  'my date of birth', 'my ssn', 'my social security', 'my username is', 'my handle is',
  'my age is', 'call me at',
];
