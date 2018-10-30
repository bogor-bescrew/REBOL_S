import Data.Aeson             (ToJSON, FromJSON)
import Data.IORef             (IORef)
import Data.Text              (Text)
import GHC.Generics           (Generic)

data SourceFile = SourceFile
  { fullPath    :: FilePath
  , sourceLines :: [Text]
  } deriving (Show)

type LineNumber = Integer

data ToodlesState = ToodlesState
  { results  :: IORef TodoListResult,
    dataPath :: FilePath
  }

data TodoEntry
  = TodoEntryHead { entryId          :: Integer
                  , body             :: [Text]
                  , assignee         :: Maybe Text
                  , sourceFile       :: FilePath
                  , lineNumber       :: LineNumber
                  , priority         :: Maybe Integer
                  , customAttributes :: [(Text, Text)]
                  , tags             :: [Text]
                  , leadingText      :: Text }
  | TodoBodyLine Text
  deriving (Show, Generic, ToJSON)

data TodoListResult = TodoListResult
  { todos   :: [TodoEntry]
  , message :: Text
  } deriving (Show, Generic, ToJSON)

newtype DeleteTodoRequest = DeleteTodoRequest
  { ids :: [Integer]
  } deriving (Show, Generic, FromJSON)

data EditTodoRequest = EditTodoRequest
  { editIds     :: [Integer]
  , setAssignee :: Maybe Text
  , addTags     :: [Text]
  , addKeyVals  :: [(Text, Text)]
  , setPriority :: Maybe Integer
} deriving (Show, Generic, FromJSON)
import Types

import           Data.Proxy         (Proxy)
import           Data.Text          (Text)
import           Servant
import           Servant.HTML.Blaze (HTML)
import           Text.Blaze.Html5   (Html)

type ToodlesAPI = "todos" :> QueryFlag "recompute" :> Get '[JSON] TodoListResult

             :<|> "todos" :> "delete" :> ReqBody '[JSON] DeleteTodoRequest :> Post '[JSON] Text

             :<|> "todos" :> "edit" :> ReqBody '[JSON] EditTodoRequest :> Post '[JSON] Text

             :<|> "static" :> Raw

             :<|> "source_file" :> Capture "id" Integer :> Get '[HTML] Html

             :<|> CaptureAll "anything-else" Text :> Get '[HTML] Html

toodlesAPI :: Proxy ToodlesAPI
toodlesAPI = Proxy
import           System.Console.CmdArgs

data ToodlesArgs = ToodlesArgs
  { directory       :: FilePath
  , assignee_search :: Maybe SearchFilter
  , limit_results   :: Int
  , port            :: Maybe Int
  , no_server       :: Bool
  } deriving (Show, Data, Typeable, Eq)

newtype SearchFilter =
  AssigneeFilter AssigneeFilterRegex
  deriving (Show, Data, Eq)

newtype AssigneeFilterRegex = AssigneeFilterRegex Text
                                  deriving (Show, Data, Eq)

argParser :: ToodlesArgs
argParser = ToodlesArgs
          { directory = def &= typFile &= help "Root directory of your project"
          , assignee_search = def &= help "Filter todo's by assignee"
          , limit_results = def &= help "Limit number of search results"
          , port = def &= help "Run server on port"
          , no_server = def &= help "Output matching todos to the command line and exit"
          } &= summary ("toodles " ++ showVersion version)
            &= program "toodles"
            &= verbosity
&= help "Manage TODO's directly from your codebase"

import ShellCheck.Analytics
import ShellCheck.AnalyzerLib
import ShellCheck.Interface
import Data.List
import Data.Monoid
import qualified ShellCheck.Checks.Commands
import qualified ShellCheck.Checks.ShellSupport


analyzeScript :: AnalysisSpec -> AnalysisResult
analyzeScript spec = newAnalysisResult {
    arComments =
        filterByAnnotation spec params . nub $
            runAnalytics spec
            ++ runChecker params (checkers params)
}
  where
    params = makeParameters spec

checkers params = mconcat $ map ($ params) [
    ShellCheck.Checks.Commands.checker,
    ShellCheck.Checks.ShellSupport.checker
]
import Test.QuickCheck.All

tokenToPosition startMap t = fromMaybe fail $ do
    span <- Map.lookup (tcId t) startMap
    return $ newPositionedComment {
        pcStartPos = fst span,
        pcEndPos = snd span,
        pcComment = tcComment t
    }
  where
    fail = error "Internal shellcheck error: id doesn't exist. Please report!"

checkScript :: Monad m => SystemInterface m -> CheckSpec -> m CheckResult
checkScript sys spec = do
    results <- checkScript (csScript spec)
    return emptyCheckResult {
        crFilename = csFilename spec,
        crComments = results
    }
  where
    checkScript contents = do
        result <- parseScript sys newParseSpec {
            psFilename = csFilename spec,
            psScript = contents,
            psCheckSourced = csCheckSourced spec,
            psShellTypeOverride = csShellTypeOverride spec
        }
        let parseMessages = prComments result
        let analysisMessages =
                fromMaybe [] $
                    (arComments . analyzeScript . analysisSpec)
                        <$> prRoot result
        let translator = tokenToPosition (prTokenPositions result)
        return . nub . sortMessages . filter shouldInclude $
            (parseMessages ++ map translator analysisMessages)

    shouldInclude pc =
        let code     = cCode (pcComment pc)
            severity = cSeverity (pcComment pc)
        in
            code `notElem` csExcludedWarnings spec &&
            severity <= csMinSeverity spec

    sortMessages = sortBy (comparing order)
    order pc =
        let pos = pcStartPos pc
            comment = pcComment pc in
        (posFile pos,
         posLine pos,
         posColumn pos,
         cSeverity comment,
         cCode comment,
         cMessage comment)
    getPosition = pcStartPos

    analysisSpec root =
        as {
            asScript = root,
            asShellType = csShellTypeOverride spec,
            asCheckSourced = csCheckSourced spec,
            asExecutionMode = Executed
         } where as = newAnalysisSpec root

getErrors sys spec =
    sort . map getCode . crComments $
        runIdentity (checkScript sys spec)
  where
    getCode = cCode . pcComment

check = checkWithIncludes []

checkWithSpec includes =
    getErrors (mockedSystemInterface includes)

checkWithIncludes includes src =
    checkWithSpec includes emptyCheckSpec {
        csScript = src,
        csExcludedWarnings = [2148]
    }

checkRecursive includes src =
    checkWithSpec includes emptyCheckSpec {
        csScript = src,
        csExcludedWarnings = [2148],
        csCheckSourced = True
    }

prop_findsParseIssue = check "echo \"$12\"" == [1037]

prop_commentDisablesParseIssue1 =
    null $ check "#shellcheck disable=SC1037\necho \"$12\""
prop_commentDisablesParseIssue2 =
    null $ check "#shellcheck disable=SC1037\n#lol\necho \"$12\""

prop_findsAnalysisIssue =
    check "echo $1" == [2086]
prop_commentDisablesAnalysisIssue1 =
    null $ check "#shellcheck disable=SC2086\necho $1"
prop_commentDisablesAnalysisIssue2 =
    null $ check "#shellcheck disable=SC2086\n#lol\necho $1"

prop_optionDisablesIssue1 =
    null $ getErrors
                (mockedSystemInterface [])
                emptyCheckSpec {
                    csScript = "echo $1",
                    csExcludedWarnings = [2148, 2086]
                }

prop_optionDisablesIssue2 =
    null $ getErrors
                (mockedSystemInterface [])
                emptyCheckSpec {
                    csScript = "echo \"$10\"",
                    csExcludedWarnings = [2148, 1037]
                }

prop_wontParseBadShell =
    [1071] == check "#!/usr/bin/python\ntrue $1\n"

prop_optionDisablesBadShebang =
    null $ getErrors
                (mockedSystemInterface [])
                emptyCheckSpec {
                    csScript = "#!/usr/bin/python\ntrue\n",
                    csShellTypeOverride = Just Sh
                }

prop_annotationDisablesBadShebang =
    [] == check "#!/usr/bin/python\n# shellcheck shell=sh\ntrue\n"


prop_canParseDevNull =
    [] == check "source /dev/null"

prop_failsWhenNotSourcing =
    [1091, 2154] == check "source lol; echo \"$bar\""

prop_worksWhenSourcing =
    null $ checkWithIncludes [("lib", "bar=1")] "source lib; echo \"$bar\""

prop_worksWhenDotting =
    null $ checkWithIncludes [("lib", "bar=1")] ". lib; echo \"$bar\""

prop_noInfiniteSourcing =
    [] == checkWithIncludes  [("lib", "source lib")] "source lib"

prop_canSourceBadSyntax =
    [1094, 2086] == checkWithIncludes [("lib", "for f; do")] "source lib; echo $1"

prop_cantSourceDynamic =
    [1090] == checkWithIncludes [("lib", "")] ". \"$1\""

prop_cantSourceDynamic2 =
    [1090] == checkWithIncludes [("lib", "")] "source ~/foo"

prop_canSourceDynamicWhenRedirected =
    null $ checkWithIncludes [("lib", "")] "#shellcheck source=lib\n. \"$1\""

prop_recursiveAnalysis =
    [2086] == checkRecursive [("lib", "echo $1")] "source lib"

prop_recursiveParsing =
    [1037] == checkRecursive [("lib", "echo \"$10\"")] "source lib"

prop_sourceDirectiveDoesntFollowFile =
    null $ checkWithIncludes
                [("foo", "source bar"), ("bar", "baz=3")]
                "#shellcheck source=foo\n. \"$1\"; echo \"$baz\""

prop_filewideAnnotationBase = [2086] == check "#!/bin/sh\necho $1"
prop_filewideAnnotation1 = null $
    check "#!/bin/sh\n# shellcheck disable=2086\necho $1"
prop_filewideAnnotation2 = null $
    check "#!/bin/sh\n# shellcheck disable=2086\ntrue\necho $1"
prop_filewideAnnotation3 = null $
    check "#!/bin/sh\n#unrelated\n# shellcheck disable=2086\ntrue\necho $1"
prop_filewideAnnotation4 = null $
    check "#!/bin/sh\n# shellcheck disable=2086\n#unrelated\ntrue\necho $1"
prop_filewideAnnotation5 = null $
    check "#!/bin/sh\n\n\n\n#shellcheck disable=2086\ntrue\necho $1"
prop_filewideAnnotation6 = null $
    check "#shellcheck shell=sh\n#unrelated\n#shellcheck disable=2086\ntrue\necho $1"
prop_filewideAnnotation7 = null $
    check "#!/bin/sh\n# shellcheck disable=2086\n#unrelated\ntrue\necho $1"

prop_filewideAnnotationBase2 = [2086, 2181] == check "true\n[ $? == 0 ] && echo $1"
prop_filewideAnnotation8 = null $
    check "# Disable $? warning\n#shellcheck disable=SC2181\n# Disable quoting warning\n#shellcheck disable=2086\ntrue\n[ $? == 0 ] && echo $1"

prop_sourcePartOfOriginalScript = -- #1181: -x disabled posix warning for 'source'
    2039 `elem` checkWithIncludes [("./saywhat.sh", "echo foo")] "#!/bin/sh\nsource ./saywhat.sh"

return []
runTests = $quickCheckAll
